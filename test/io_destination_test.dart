@Tags(['integration'])
library;

import 'dart:io';

import 'package:doh_transport/doh_transport_io.dart';
import 'package:test/test.dart';

import 'support/dns_wire.dart';
import 'support/scripted_server.dart';
import 'support/test_pki.dart';

void main() {
  // No IP names: a handshake succeeds only if TLS checks the URI host.
  late TestPki pki;
  late ScriptedServer server;
  setUpAll(() =>
      pki = TestPki.generate(dnsNames: ['resolver.example'], ipAddresses: []));
  setUp(() async {
    server = ScriptedServer(
        pki.serverContext(), (e) => e.send(httpResponse(wireReply(id: e.id))));
    await server.start();
  });
  tearDown(() => server.close());

  Uri endpoint([String host = 'resolver.example']) =>
      Uri.parse('https://$host:${server.port}/dns-query');

  IoDohTransport transport({SecurityContext? trust}) {
    final transport = IoDohTransport(
        securityContext: trust ?? pki.clientContext(),
        destination: InternetAddress.loopbackIPv4);
    addTearDown(transport.close);
    return transport;
  }

  test('connects to the destination and authenticates the URI host', () async {
    final t = transport();
    for (final id in [1, 2]) {
      final response = await t
          .startWire(endpoint(), wireQuery(id: id), maxResponseBytes: 512)
          .result;
      expect(response.body.sublist(0, 2), u16(id));
    }
    expect(server.connections, 1, reason: 'direct reuse still applies');
    expect(server.exchanges, hasLength(2));
  });

  test('a certificate for another host is rejected', () async {
    await expectLater(
        transport()
            .startWire(endpoint('other.example'), wireQuery(),
                maxResponseBytes: 512)
            .result,
        throwsA(isA<DohConnectionException>()));
    expect(server.exchanges, isEmpty);
  });

  test('an untrusted CA at the destination is rejected', () async {
    await expectLater(
        transport(trust: TestPki.generate().clientContext())
            .startWire(endpoint(), wireQuery(), maxResponseBytes: 512)
            .result,
        throwsA(isA<DohConnectionException>()));
    expect(server.exchanges, isEmpty);
  });

  test('a destination must be a numeric address', () {
    expect(
        () => IoDohTransport(
            destination: InternetAddress('/s', type: InternetAddressType.unix)),
        throwsArgumentError);
  });
}
