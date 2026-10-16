import 'dart:collection';
import 'dart:math';

import 'package:doh_transport/doh_transport.dart';
import 'package:doh_transport/src/wire.dart';
import 'package:test/test.dart';

import 'support/dns_wire.dart';

const pointer = [0xc0, 12];

// Counts byte reads, so the work a hostile response causes is measurable.
class CountingBytes extends ListBase<int> {
  final List<int> bytes;
  int reads = 0;
  CountingBytes(this.bytes);
  @override
  int get length => bytes.length;
  @override
  set length(int value) => throw UnsupportedError('immutable');
  @override
  int operator [](int index) {
    reads++;
    return bytes[index];
  }

  @override
  void operator []=(int index, int value) =>
      throw UnsupportedError('immutable');
}

void main() {
  final query = wireQuery();

  test('accepts a reply without reading its records', () {
    validateDnsWireResponse(
        query,
        wireReply(answers: [
          wireRecord(pointer, 5, [3, ...'pay'.codeUnits, 0xc0, 18]),
          wireRecord(wireName('pay.example'), 16, txtRdata('oa1:xmr')),
        ]));
    validateDnsWireResponse(query, wireReply(flags: 0x8183));
    validateDnsWireResponse(query, [...wireReply(), 0]);
    validateDnsWireResponse(query, wireReply()..[7] = 255);
  });

  test('reads only the header and question of a large hostile reply', () {
    final response = CountingBytes(wireReply(answers: [
      for (var i = 0; i < 5000; i++) wireRecord([0xc0, 12], 99, [])
    ]));
    validateDnsWireResponse(query, response);
    expect(response.reads, lessThan(64));
  });

  test('question comparison folds ASCII case in the name only', () {
    validateDnsWireResponse(query, wireReply(name: 'ALICE.example'));
    expect(
        () => validateDnsWireResponse(query, wireReply(name: 'alicf.example')),
        throwsA(isA<DohQuestionMismatchException>()));
    // The low octet of type 65 is 'A'; type 97 must not match it.
    final https = wireQuery(type: 65);
    validateDnsWireResponse(https, wireEcho(https));
    expect(() => validateDnsWireResponse(https, wireEcho(https)..[28] = 97),
        throwsA(isA<DohQuestionMismatchException>()));
  });

  test('rejects replies that do not answer the query', () {
    for (final reply in [
      wireReply(id: 0x4321),
      wireReply(flags: 0x8980),
      wireReply(name: 'bob.example'),
      [...wireHeader(flags: 0x8180, qd: 0)],
      wireReply()..[query.length - 11 - 3] = 1,
      wireReply()..[query.length - 11 - 1] = 3,
    ]) {
      expect(() => validateDnsWireResponse(query, reply),
          throwsA(isA<DohQuestionMismatchException>()));
    }
  });

  test('rejects queries as replies and truncated replies', () {
    for (final reply in [query, wireReply(flags: 0x8380)]) {
      expect(() => validateDnsWireResponse(query, reply),
          throwsA(isA<DohMalformedResponseException>()));
    }
    expect(() => validateDnsWireResponse(wireReply(), wireReply()),
        throwsA(isA<DohInvalidQueryException>()));
  });

  test('requires exactly one question in the query', () {
    final none = wireHeader(qd: 0);
    final question = query.sublist(12, 31);
    final two = [
      ...wireHeader(qd: 2, ar: 1),
      ...question,
      ...query.sublist(12)
    ];
    for (final bad in [none, two]) {
      expect(() => validateDnsWireResponse(bad, wireEcho(bad)),
          throwsA(isA<DohInvalidQueryException>()));
      expect(
          () => padDnsWireQuery(bad), throwsA(isA<DohInvalidQueryException>()));
    }
    expect(() => validateDnsWireResponse(query, wireEcho(two)),
        throwsA(isA<DohQuestionMismatchException>()));
  });

  group('malformed replies fail closed', () {
    final cases = <String, List<int>>{
      'short header': wireReply().sublist(0, 11),
      'question past end': wireReply().sublist(0, 20),
      'question type and class cut short': wireReply().sublist(0, 29),
      'label past end': [...wireHeader(flags: 0x8180), 40, 0x61],
      'compressed question': [
        ...wireHeader(flags: 0x8180),
        ...wireQuestion(pointer),
      ],
      'extended label type': [
        ...wireHeader(flags: 0x8180),
        ...wireQuestion([0x41, 0]),
      ],
      'question name over 255 octets': [
        ...wireHeader(flags: 0x8180),
        ...wireQuestion([
          for (var i = 0; i < 4; i++) ...[63, ...List.filled(63, 0x61)],
          0
        ]),
      ],
    };
    cases.forEach((name, reply) {
      test(name, () {
        expect(() => validateDnsWireResponse(query, reply),
            throwsA(isA<DohMalformedResponseException>()));
      });
    });
  });

  test('random corruption never escapes as a non-DNS error', () {
    final random = Random(8484);
    final valid = wireReply(answers: [
      wireRecord(pointer, 5, [3, ...'pay'.codeUnits, 0xc0, 18]),
      wireRecord(wireName('pay.example'), 16, txtRdata('oa1:xmr')),
    ]);
    for (var i = 0; i < 5000; i++) {
      final reply = [...valid];
      for (var j = random.nextInt(4); j >= 0; j--) {
        reply[random.nextInt(reply.length)] = random.nextInt(256);
      }
      final cut = random.nextInt(8) == 0 ? random.nextInt(reply.length) : null;
      try {
        validateDnsWireResponse(
            query, cut == null ? reply : reply.sublist(0, cut));
      } on DohTransportException {
        // Expected for most mutations.
      }
    }
  });

  group('query padding', () {
    test('pads a final OPT record to a 128-octet block', () {
      final padded = padDnsWireQuery(query);
      expect(padded.length % 128, 0);
      final option = padded.sublist(query.length);
      expect(option.sublist(0, 2), [0, 12]);
      expect(option.sublist(2, 4), u16(padded.length - query.length - 4));
      expect(option.skip(4), everyElement(0));
      expect(padded.sublist(query.length - 2, query.length),
          u16(padded.length - query.length));
      validateDnsWireResponse(padded, wireReply());
      expect(padDnsWireQuery(padded), padded);
    });

    test('skips compressed record owners before the OPT record', () {
      final compressed = [
        ...wireHeader(ar: 2),
        ...wireQuestion(wireName('alice.example')),
        ...wireRecord(pointer, 16, txtRdata('x')),
        ...wireOpt(),
      ];
      expect(padDnsWireQuery(compressed).length % 128, 0);
    });

    test('leaves queries without a final OPT record unchanged', () {
      final plain = wireQuery(edns: false);
      expect(padDnsWireQuery(plain), plain);
      final optFirst = [
        ...wireHeader(ar: 2),
        ...wireQuestion(wireName('alice.example')),
        ...wireOpt(),
        ...wireRecord([0], 16, txtRdata('x'))
      ];
      expect(padDnsWireQuery(optFirst), optFirst);
    });

    test('rejects invalid queries', () {
      for (final bad in [
        <int>[],
        [...query, 0],
        wireReply(),
        [...query]..[0] = 256,
        wireHeader(qd: 0),
        [...query]..[11] = 2,
        [...wireHeader(), ...wireQuestion(pointer)],
        [
          ...wireHeader(ar: 1),
          ...wireQuestion(wireName('alice.example')),
          ...wireRecord([0x41, 0], 16, []),
        ],
        [
          ...wireHeader(ar: 1),
          ...wireQuestion(wireName('alice.example')),
          ...wireOpt(options: [0, 12, 0, 9, 0]),
        ],
      ]) {
        expect(() => padDnsWireQuery(bad),
            throwsA(isA<DohInvalidQueryException>()));
        expect(() => checkedDnsWireQuery(bad),
            throwsA(isA<DohInvalidQueryException>()));
      }
    });
  });
}
