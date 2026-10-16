@Tags(['integration'])
library;

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:doh_transport/src/tls_connection.dart';
import 'package:test/test.dart';

import 'support/test_pki.dart';

const second = Duration(seconds: 2);

Uint8List pattern(int length) =>
    Uint8List.fromList([for (var i = 0; i < length; i++) i * 7 & 0xff]);

Stream<List<int>> chunks(Uint8List body, {int size = 1 << 16}) =>
    Stream.fromIterable([
      for (var at = 0; at < body.length; at += size)
        Uint8List.sublistView(body, at, at + size)
    ]);

void main() {
  late TestPki pki;
  late SecureServerSocket server;
  late StreamIterator<SecureSocket> accepted;
  final open = <Socket>[];
  setUpAll(() => pki = TestPki.generate());
  setUp(() async {
    server = await SecureServerSocket.bind(
        InternetAddress.loopbackIPv4, 0, pki.serverContext());
    accepted = StreamIterator(server);
  });
  tearDown(() async {
    for (final socket in open) {
      socket.destroy();
    }
    open.clear();
    await accepted.cancel();
  });

  Future<(Socket, SecureSocket)> connect({int? port}) async {
    final next = accepted.moveNext();
    final client = await connectTls(
            InternetAddress.loopbackIPv4, port ?? server.port,
            tlsHost: 'localhost', context: pki.clientContext(), timeout: second)
        .socket;
    expect(await next, isTrue);
    open.addAll([client, accepted.current]);
    return (client, accepted.current);
  }

  test('a large write waits for the peer and arrives intact', () async {
    final (client, peer) = await connect();
    final body = pattern(16 << 20);
    var pauses = 0;
    final source = StreamController<List<int>>(onPause: () => pauses++);
    unawaited(source.addStream(chunks(body)).then((_) => source.close()));
    var sent = false;
    final sending = client.addStream(source.stream).then((_) => sent = true);
    await Future<void>.delayed(const Duration(milliseconds: 200));
    expect(sent, isFalse, reason: 'the peer has not read yet');
    expect(pauses, greaterThan(0));
    final received = BytesBuilder(copy: false);
    final reading = peer.listen(received.add);
    addTearDown(reading.cancel);
    await sending.timeout(const Duration(seconds: 20));
    while (received.length < body.length) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
    expect(received.takeBytes(), body);
  });

  test('a peer that closes mid-write fails the write and done', () async {
    final (client, peer) = await connect();
    final sending = client.addStream(chunks(pattern(16 << 20)));
    await Future<void>.delayed(const Duration(milliseconds: 100));
    peer.destroy();
    await expectLater(sending.timeout(second), throwsA(isA<IOException>()));
    await expectLater(client.done.timeout(second), throwsA(isA<IOException>()));
  });

  test('a failing source fails the write and done, not the stream', () async {
    final (client, _) = await connect();
    final streamErrors = <Object>[];
    final ended = Completer<void>();
    client.listen((_) {},
        onError: streamErrors.add, onDone: () => ended.complete());
    final failure = StateError('source failed');
    await expectLater(
        client.addStream(Stream<List<int>>.error(failure)), throwsA(failure));
    await expectLater(client.done, throwsA(failure));
    await ended.future.timeout(second);
    expect(streamErrors, isEmpty);
  });

  test('writes after destroy fail', () async {
    final (client, _) = await connect();
    client.destroy();
    await expectLater(
        client.addStream(Stream.value([1])), throwsA(isA<SocketException>()));
    client.add([1]);
    await expectLater(client.flush(), throwsA(isA<SocketException>()));
    await expectLater(client.close(), throwsA(isA<SocketException>()));
  });

  test('done completes when destroyed, and the peer sees the close', () async {
    final (client, peer) = await connect();
    final peerClosed = peer.drain<void>().then((_) {}, onError: (Object _) {});
    client.destroy();
    await client.done.timeout(second);
    await peerClosed.timeout(second);
  });

  test('done and the stream complete when the peer closes', () async {
    final (client, peer) = await connect();
    final ended = client.drain<void>();
    peer.destroy();
    await ended.timeout(second);
    await client.done.timeout(second);
    await expectLater(
        client.addStream(Stream.value([1])), throwsA(isA<SocketException>()));
  });

  test('a socket shut down in both directions ends', () async {
    final (client, _) = await connect();
    final reading = client.listen((_) {});
    await reading.cancel();
    await client.close();
    await client.done.timeout(second);
    await expectLater(
        client.addStream(Stream.value([1])), throwsA(isA<SocketException>()));
  });

  test('pausing the stream loses no bytes', () async {
    final (client, peer) = await connect();
    final body = pattern(4 << 20);
    peer.add(body);
    unawaited(peer.close());
    final received = BytesBuilder(copy: false);
    final finished = Completer<void>();
    var pauses = 0;
    late StreamSubscription<Uint8List> reading;
    reading = client.listen((chunk) {
      received.add(chunk);
      if (pauses < 5) {
        pauses++;
        reading.pause(Future<void>.delayed(const Duration(milliseconds: 20)));
      }
    }, onDone: finished.complete);
    await finished.future.timeout(const Duration(seconds: 10));
    expect(pauses, 5);
    expect(received.takeBytes(), body);
  });

  test('a raw socket error reaches the stream, a write and done', () async {
    final relay = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final toClient = Completer<Socket>();
    relay.listen((downstream) async {
      final upstream =
          await Socket.connect(InternetAddress.loopbackIPv4, server.port);
      open.addAll([downstream, upstream]);
      downstream.listen(upstream.add, onError: (Object _) {});
      upstream.listen(downstream.add, onError: (Object _) {});
      toClient.complete(downstream);
    });
    addTearDown(relay.close);
    final (client, _) = await connect(port: relay.port);
    final streamError = Completer<Object>();
    client.listen((_) {}, onError: (Object error) {
      if (!streamError.isCompleted) streamError.complete(error);
    });
    final source = StreamController<List<int>>();
    addTearDown(source.close);
    final sending = client.addStream(source.stream);
    (await toClient.future).add(List.filled(32, 0xff));
    final error = await streamError.future.timeout(second);
    expect(error, isA<IOException>());
    await expectLater(sending, throwsA(same(error)));
    await expectLater(client.done, throwsA(same(error)));
    client.add([1]);
    await expectLater(client.flush(), throwsA(same(error)));
  });
}
