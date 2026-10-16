@Tags(['integration'])
library;

import 'dart:async';
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

  IoDohTransport transport(
      {SecurityContext? trust, Duration? connectionTimeout}) {
    final transport = IoDohTransport(
        securityContext: trust ?? pki.clientContext(),
        destination: InternetAddress.loopbackIPv4,
        connectionTimeout: connectionTimeout ?? const Duration(seconds: 5));
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

  test('stalled handshakes time out and close every peer', () async {
    final silent = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(silent.close);
    final accepted = <Socket>[];
    final peerClosed = <Future<void>>[];
    silent.listen((socket) {
      accepted.add(socket);
      final closed = Completer<void>();
      void finish() {
        if (!closed.isCompleted) closed.complete();
      }

      socket.listen((_) {}, onError: (Object _) => finish(), onDone: finish);
      peerClosed.add(closed.future);
    });
    addTearDown(() {
      for (final socket in accepted) {
        socket.destroy();
      }
    });
    final t = transport(connectionTimeout: const Duration(milliseconds: 200));
    final started = DateTime.now();
    for (var id = 1; id <= 3; id++) {
      await expectLater(
          t
              .startWire(
                  Uri.parse(
                      'https://resolver.example:${silent.port}/dns-query'),
                  wireQuery(id: id),
                  maxResponseBytes: 512)
              .result,
          throwsA(isA<DohConnectionTimeoutException>()));
      expect(accepted, hasLength(id));
      await peerClosed.last.timeout(const Duration(seconds: 2));
    }
    expect(DateTime.now().difference(started).inSeconds, lessThan(2));
    expect(peerClosed, hasLength(accepted.length));
  });

  test('cancelling a stalled handshake closes the peer', () async {
    final silent = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    addTearDown(silent.close);
    final accepted = Completer<Socket>();
    final peerClosed = Completer<void>();
    silent.listen((socket) {
      accepted.complete(socket);
      void finish() {
        if (!peerClosed.isCompleted) peerClosed.complete();
      }

      socket.listen((_) {}, onError: (Object _) => finish(), onDone: finish);
    });
    addTearDown(() async {
      if (accepted.isCompleted) (await accepted.future).destroy();
    });
    final operation = transport().startWire(
        Uri.parse('https://resolver.example:${silent.port}/dns-query'),
        wireQuery(),
        maxResponseBytes: 512);
    final failed =
        expectLater(operation.result, throwsA(isA<DohCancelledException>()));
    await accepted.future;
    operation.cancel();
    await failed;
    await peerClosed.future.timeout(const Duration(seconds: 2));
  });

  test('a destination must be a numeric address', () {
    expect(
        () => IoDohTransport(
            destination: InternetAddress('/s', type: InternetAddressType.unix)),
        throwsArgumentError);
  });
}
