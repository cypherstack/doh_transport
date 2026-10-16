import 'dart:typed_data';

import 'exceptions.dart';

const _malformed = DohMalformedResponseException('Malformed DNS wire message');
const _mismatch =
    DohQuestionMismatchException('DNS wire response does not match query');
const _invalidQuery = DohInvalidQueryException('Invalid DNS wire query');

/// Checks that wire [response] answers [query]: a response with the same ID,
/// opcode and single question, not truncated. Only the header and question
/// are read, so the work is bounded by the question; the records are left to
/// the caller's parser. Throws [DohInvalidQueryException] for an unusable
/// [query].
void validateDnsWireResponse(List<int> query, List<int> response) {
  final sent = _parseQuery(query);
  if (response.length < 12 || response.length > 65535) throw _malformed;
  final flags = _u16(response, 2);
  if (flags & 0x8000 == 0) throw _malformed;
  if (flags & 0x0200 != 0) {
    throw const DohMalformedResponseException('Truncated DNS wire response');
  }
  if (_u16(response, 0) != _u16(query, 0) ||
      flags >> 11 & 0xf != query[2] >> 3 & 0xf ||
      _u16(response, 4) != 1) {
    throw _mismatch;
  }
  final end = _questionEnd(response) ?? (throw _malformed);
  if (end != sent.questionEnd) throw _mismatch;
  for (var i = 12; i < end; i++) {
    final a = query[i];
    final b = response[i];
    // Length octets are below 'A', so only name characters fold.
    if (a != b && (i >= end - 4 || _lower(a) != _lower(b))) throw _mismatch;
  }
}

/// Pads [query] to a multiple of [blockSize] octets with an RFC 7830
/// padding option, as RFC 8467 recommends. Queries without a final OPT
/// record or already padded are returned unchanged.
List<int> padDnsWireQuery(List<int> query, {int blockSize = 128}) {
  if (blockSize < 1 || blockSize > 512) {
    throw ArgumentError.value(blockSize, 'blockSize');
  }
  final rdlength = _parseQuery(query).optRdlength;
  if (rdlength == null) return List<int>.unmodifiable(query);
  final padding = (blockSize - (query.length + 4) % blockSize) % blockSize;
  final length = query.length + 4 + padding;
  final optLength = _u16(query, rdlength) + 4 + padding;
  if (length > 65535 || optLength > 65535) {
    return List<int>.unmodifiable(query);
  }
  final padded = Uint8List(length)
    ..setRange(0, query.length, query)
    ..[rdlength] = optLength >> 8
    ..[rdlength + 1] = optLength & 0xff
    ..[query.length] = 0
    ..[query.length + 1] = 12
    ..[query.length + 2] = padding >> 8
    ..[query.length + 3] = padding & 0xff;
  return List<int>.unmodifiable(padded);
}

List<int> checkedDnsWireQuery(List<int> query) {
  _parseQuery(query);
  return List<int>.unmodifiable(query);
}

int _u16(List<int> data, int offset) => data[offset] << 8 | data[offset + 1];

int _lower(int c) => c >= 0x41 && c <= 0x5a ? c + 32 : c;

/// The end of the question at offset 12, or null if it is cut short, longer
/// than 255 octets, or compressed: as the first name in the message, a
/// pointer has nothing to refer to.
int? _questionEnd(List<int> message) {
  var at = 12;
  while (true) {
    if (at >= message.length) return null;
    final length = message[at];
    if (length == 0) break;
    if (length < 0 || length > 63) return null;
    at += 1 + length;
    if (at - 12 > 254) return null;
  }
  at += 5;
  return at <= message.length ? at : null;
}

/// The offset after the name at [at], without following compression
/// pointers, or null if it runs past [end].
int? _skipName(List<int> message, int at, int end) {
  while (at < end) {
    final length = message[at];
    if (length == 0) return at + 1;
    if (length & 0xc0 == 0xc0) return at + 2 <= end ? at + 2 : null;
    if (length > 63) return null;
    at += 1 + length;
  }
  return null;
}

/// Checks that [query] is a query with one question whose records frame it
/// exactly. Returns the end of the question and the RDLENGTH offset of an
/// unpadded OPT record that ends the query, if there is one.
({int questionEnd, int? optRdlength}) _parseQuery(List<int> query) {
  if (query.length < 12 ||
      query.length > 65535 ||
      query.any((byte) => byte < 0 || byte > 255) ||
      query[2] & 0x80 != 0 ||
      _u16(query, 4) != 1) {
    throw _invalidQuery;
  }
  final questionEnd = _questionEnd(query) ?? (throw _invalidQuery);
  final additional = _u16(query, 10);
  final records = _u16(query, 6) + _u16(query, 8) + additional;
  var at = questionEnd;
  int? optRdlength;
  for (var i = 0; i < records; i++) {
    final owner = at;
    at = _skipName(query, at, query.length) ?? (throw _invalidQuery);
    if (at + 10 > query.length) throw _invalidQuery;
    final start = at + 10;
    final end = start + _u16(query, at + 8);
    if (end > query.length) throw _invalidQuery;
    optRdlength = null;
    if (i == records - 1 &&
        additional > 0 &&
        _u16(query, at) == 41 &&
        query[owner] == 0) {
      optRdlength = at + 8;
      for (var option = start; option < end;) {
        if (option + 4 > end) throw _invalidQuery;
        if (_u16(query, option) == 12) optRdlength = null;
        option += 4 + _u16(query, option + 2);
        if (option > end) throw _invalidQuery;
      }
    }
    at = end;
  }
  if (at != query.length) throw _invalidQuery;
  return (questionEnd: questionEnd, optRdlength: optRdlength);
}
