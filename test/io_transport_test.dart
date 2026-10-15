@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:doh_transport/doh_transport_io.dart';
import 'package:test/test.dart';
import 'support/test_pki.dart';
import 'support/tunnel_proxy.dart';

List<int> jsonReply([String value = 'oa1:xmr recipient_address=valid;']) =>
    utf8.encode(jsonEncode({
      'Status': 0,
      'AD': true,
      'CD': false,
      'TC': false,
      'Question': [
        {'name': 'alice.example.', 'type': 16}
      ],
      'Answer': [
        {'name': 'alice.example.', 'type': 16, 'TTL': 60, 'data': value}
      ],
    }));

void main() {
  late HttpServer server;
  late SecurityContext trust;
  late TestPki pki;
  setUpAll(() => pki = TestPki.generate());
  setUp(() async {
    trust = pki.clientContext();
    server = await HttpServer.bindSecure(
        InternetAddress.loopbackIPv4, 0, pki.serverContext());
  });
  tearDown(() => server.close(force: true));
  Uri endpoint() =>
      Uri.parse('https://localhost:${server.port}/resolve').replace(
        queryParameters: {
          'name': 'alice.example.',
          'type': 'TXT',
          'do': 'true',
          'cd': 'false',
          'edns_client_subnet': '0.0.0.0/0',
        },
      );

  for (final proxied in [false, true]) {
    test('authenticated TXT over ${proxied ? 'SOCKS' : 'direct'} HTTPS',
        () async {
      var requests = 0;
      server.listen((request) {
        requests++;
        expect(request.uri.queryParameters['name'], 'alice.example.');
        expect(request.uri.queryParameters['do'], 'true');
        expect(request.uri.queryParameters['cd'], 'false');
        expect(request.uri.queryParameters['edns_client_subnet'], '0.0.0.0/0');
        expect(request.headers.value('accept'), 'application/dns-json');
        request.response.headers.contentType = ContentType.json;
        request.response.add(jsonReply());
        request.response.close();
      });
      final proxy = TunnelProxy(upstreamPort: server.port, fragmented: true);
      if (proxied) {
        await proxy.start();
        addTearDown(proxy.close);
      }
      final transport = IoDohTransport(
          securityContext: trust,
          proxy: proxied
              ? SocksProxy(InternetAddress.loopbackIPv4, proxy.port)
              : null,
          destination: proxied ? InternetAddress('8.8.8.8') : null);
      final response =
          await transport.start(endpoint(), maxResponseBytes: 65536).result;
      expect(jsonDecode(utf8.decode(response.body))['Answer'][0]['data'],
          'oa1:xmr recipient_address=valid;');
      expect(requests, 1);
      if (proxied) {
        expect(proxy.target, '8.8.8.8');
        await transport.close();
        await proxy.disconnected.future.timeout(const Duration(seconds: 2));
      }
    });
  }
  test('a rejected required proxy never falls back to reachable direct HTTPS',
      () async {
    var requests = 0;
    server.listen((request) {
      requests++;
      request.response.close();
    });
    final proxy = TunnelProxy(replyCode: 5);
    await proxy.start();
    addTearDown(proxy.close);
    final transport = IoDohTransport(
        securityContext: trust,
        proxy: SocksProxy(InternetAddress.loopbackIPv4, proxy.port));
    await expectLater(
        transport.start(endpoint(), maxResponseBytes: 65536).result,
        throwsA(isA<DohConnectionException>()));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(requests, 0);
    expect(proxy.connections, 1);
  });
  test('HTTPS identity must be trusted', () async {
    server.listen((r) => r.response.close(), onError: (Object _) {});
    await expectLater(
        IoDohTransport().start(endpoint(), maxResponseBytes: 65536).result,
        throwsA(isA<DohConnectionException>()));
  });
  test('redirects never produce a second request', () async {
    var requests = 0;
    server.listen((r) {
      requests++;
      r.response.statusCode = 302;
      r.response.headers
          .set('location', endpoint().replace(path: '/redirected').toString());
      r.response.close();
    });
    await expectLater(
        IoDohTransport(securityContext: trust)
            .start(endpoint(), maxResponseBytes: 65536)
            .result,
        throwsA(isA<DohHttpStatusException>()
            .having((error) => error.statusCode, 'statusCode', 302)));
    expect(requests, 1);
  });
  test('streaming response size limit aborts before parsing', () async {
    server.listen((r) {
      r.response.headers.contentType = ContentType.json;
      r.response.write('x' * 129);
      r.response.close();
    });
    await expectLater(
        IoDohTransport(securityContext: trust)
            .start(endpoint(), maxResponseBytes: 128)
            .result,
        throwsA(isA<DohResponseTooLargeException>()));
  });
  for (final cancel in [false, true]) {
    test('${cancel ? 'cancel' : 'timeout'} destroys stalled response transport',
        () async {
      final sent = Completer<void>();
      server.listen((r) async {
        r.response.headers.contentType = ContentType.json;
        r.response.write('{');
        await r.response.flush();
        if (!sent.isCompleted) sent.complete();
      });
      final proxy = TunnelProxy(upstreamPort: server.port);
      await proxy.start();
      addTearDown(proxy.close);
      final transport = IoDohTransport(
          securityContext: trust,
          requestTimeout: const Duration(milliseconds: 300),
          proxy: SocksProxy(InternetAddress.loopbackIPv4, proxy.port));
      final operation = transport.start(endpoint(), maxResponseBytes: 65536);
      final failed = expectLater(
          operation.result,
          throwsA(cancel
              ? isA<DohCancelledException>()
              : isA<DohRequestTimeoutException>()));
      await sent.future;
      if (cancel) operation.cancel();
      await failed;
      await proxy.disconnected.future.timeout(const Duration(seconds: 2));
    });
  }
  test('generated test certificate is a short-lived serverAuth leaf', () async {
    server.listen((r) => r.response.close());
    final socket =
        await SecureSocket.connect('localhost', server.port, context: trust);
    final leaf = socket.peerCertificate!;
    socket.destroy();
    final now = DateTime.now();
    expect(leaf.issuer, contains('doh_resolver test CA'));
    expect(leaf.subject, isNot(leaf.issuer));
    expect(leaf.startValidity.isBefore(now), isTrue);
    expect(leaf.endValidity.difference(leaf.startValidity).inDays,
        lessThanOrEqualTo(31));
    await expectLater(
        SecureSocket.connect('localhost', server.port,
            context: TestPki.generate().clientContext()),
        throwsA(isA<HandshakeException>()));
  });
  test('requests identity encoding without a client fingerprint', () async {
    server.listen((r) {
      expect(r.headers[HttpHeaders.acceptEncodingHeader], isNull);
      expect(r.headers[HttpHeaders.userAgentHeader], isNull);
      r.response.headers.contentType = ContentType.json;
      r.response.add(jsonReply());
      r.response.close();
    });
    final result = await IoDohTransport(securityContext: trust)
        .start(endpoint(), maxResponseBytes: 65536)
        .result;
    expect(result.body, isNotEmpty);
  });
  for (final (header, seconds) in [
    (null, 0),
    ('250', 250),
    (' 7 ', 7),
    ('000000000001', 1),
    ('00000000000000000000', 0),
    ('2147483648', 0x80000000),
    ('99999999999', 0x80000000),
    ('000099999999999', 0x80000000),
    ('250, 0', 250),
    ('5,abc', 5),
    (', 5', 0),
    ('-5', 0),
    ('1.5', 0),
    ('abc', 0),
  ]) {
    test('reports HTTP Age header $header as $seconds seconds', () async {
      server.listen((r) {
        r.response.headers.contentType = ContentType.json;
        if (header != null) {
          r.response.headers.set(HttpHeaders.ageHeader, header);
        }
        r.response.add(jsonReply());
        r.response.close();
      });
      final response = await IoDohTransport(securityContext: trust)
          .start(endpoint(), maxResponseBytes: 65536)
          .result;
      expect(response.age, Duration(seconds: seconds));
    });
  }
  test('uses the first of repeated HTTP Age headers', () async {
    server.listen((r) {
      r.response.headers
        ..contentType = ContentType.json
        ..add(HttpHeaders.ageHeader, '250')
        ..add(HttpHeaders.ageHeader, '0');
      r.response.add(jsonReply());
      r.response.close();
    });
    final response = await IoDohTransport(securityContext: trust)
        .start(endpoint(), maxResponseBytes: 65536)
        .result;
    expect(response.age, const Duration(seconds: 250));
  });
  for (final (type, encoding) in [
    (null, null),
    (ContentType.text, null),
    (ContentType.html, null),
    (ContentType.json, 'gzip'),
  ]) {
    test('rejects JSON body typed $type encoded $encoding', () async {
      server.listen((r) {
        if (type != null) r.response.headers.contentType = type;
        if (encoding != null) {
          r.response.headers.set(HttpHeaders.contentEncodingHeader, encoding);
        }
        r.response.add(jsonReply());
        r.response.close();
      });
      await expectLater(
          IoDohTransport(securityContext: trust)
              .start(endpoint(), maxResponseBytes: 65536)
              .result,
          throwsA(isA<DohMalformedResponseException>()));
    });
  }
}
