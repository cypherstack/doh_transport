import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Produces a response body for one recorded fake HTTP request.
typedef FakeDohReply = FutureOr<List<int>> Function(Uri uri, List<int> body);

/// HTTP behavior applied to one request handled by [FakeDohHttpClient].
final class FakeDohHttpScript {
  final int statusCode;
  final String? contentType;
  final String? age;
  final String? contentEncoding;
  final int? declaredContentLength;
  final List<int>? chunkSizes;
  final Duration delay;
  final bool hang;
  final Object? openUrlError;
  final Object? midBodyError;

  const FakeDohHttpScript({
    this.statusCode = 200,
    this.contentType = 'application/dns-message',
    this.age,
    this.contentEncoding,
    this.declaredContentLength,
    this.chunkSizes,
    this.delay = Duration.zero,
    this.hang = false,
    this.openUrlError,
    this.midBodyError,
  });
}

/// One request observed by [FakeDohHttpClient].
final class FakeDohHttpRequestRecord {
  final String method;
  final Uri uri;
  final FakeDohHttpHeaders headers;
  final List<int> body;
  bool aborted = false;

  FakeDohHttpRequestRecord(this.method, this.uri, this.headers, this.body);
}

/// A socket-free [HttpClient] fake for exercising [IoDohTransport].
///
/// Pass [create] as `IoDohTransport.httpClientFactory`. Each call returns a
/// separate client that shares this fake's scripts and records.
final class FakeDohHttpClient implements HttpClient {
  final FakeDohReply reply;
  final List<FakeDohHttpScript> scripts;
  final List<FakeDohHttpRequestRecord> requests = [];
  final List<SecurityContext?> contexts = [];
  final Set<_FakeDohHttpClientRequest> _active = {};
  int _opened = 0;
  int _inFlight = 0;
  int createdClients = 0;
  int maxActiveRequests = 0;
  int aborts = 0;
  int closes = 0;

  FakeDohHttpClient({required this.reply, this.scripts = const []});

  HttpClient create(SecurityContext? context) {
    createdClients++;
    contexts.add(context);
    return _FakeDohHttpClientLane(this);
  }

  @override
  Duration? connectionTimeout;
  @override
  Duration idleTimeout = const Duration(seconds: 15);
  @override
  int? maxConnectionsPerHost = 6;
  @override
  bool autoUncompress = true;
  @override
  String? userAgent;
  @override
  String Function(Uri url)? findProxy;
  @override
  Future<ConnectionTask<Socket>> Function(
      Uri url, String? proxyHost, int? proxyPort)? connectionFactory;

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) =>
      _open(method, url, _active);

  @override
  void close({bool force = false}) => _close(_active, force: force);

  Future<HttpClientRequest> _open(
      String method, Uri url, Set<_FakeDohHttpClientRequest> active) async {
    final index = _opened++;
    final script =
        index < scripts.length ? scripts[index] : const FakeDohHttpScript();
    if (script.openUrlError case final error?) throw error;
    final request =
        _FakeDohHttpClientRequest(this, active, method, url, script);
    active.add(request);
    if (++_inFlight > maxActiveRequests) maxActiveRequests = _inFlight;
    return request;
  }

  void _close(Set<_FakeDohHttpClientRequest> active, {required bool force}) {
    closes++;
    if (force) {
      for (final request in [...active]) {
        request.abort();
      }
    }
  }

  void _finished(_FakeDohHttpClientRequest request) {
    if (request.active.remove(request)) _inFlight--;
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnimplementedError('FakeDohHttpClient: ${invocation.memberName}');
}

/// One client handed to a transport lane; settings and records are shared.
final class _FakeDohHttpClientLane implements HttpClient {
  final FakeDohHttpClient parent;
  final Set<_FakeDohHttpClientRequest> _active = {};

  _FakeDohHttpClientLane(this.parent);

  @override
  Duration? get connectionTimeout => parent.connectionTimeout;
  @override
  set connectionTimeout(Duration? value) => parent.connectionTimeout = value;
  @override
  Duration get idleTimeout => parent.idleTimeout;
  @override
  set idleTimeout(Duration value) => parent.idleTimeout = value;
  @override
  int? get maxConnectionsPerHost => parent.maxConnectionsPerHost;
  @override
  set maxConnectionsPerHost(int? value) => parent.maxConnectionsPerHost = value;
  @override
  bool get autoUncompress => parent.autoUncompress;
  @override
  set autoUncompress(bool value) => parent.autoUncompress = value;
  @override
  String? get userAgent => parent.userAgent;
  @override
  set userAgent(String? value) => parent.userAgent = value;
  String Function(Uri url)? get findProxy => parent.findProxy;
  @override
  set findProxy(String Function(Uri url)? value) => parent.findProxy = value;
  Future<ConnectionTask<Socket>> Function(
          Uri url, String? proxyHost, int? proxyPort)?
      get connectionFactory => parent.connectionFactory;
  @override
  set connectionFactory(
          Future<ConnectionTask<Socket>> Function(
                  Uri url, String? proxyHost, int? proxyPort)?
              value) =>
      parent.connectionFactory = value;

  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) =>
      parent._open(method, url, _active);

  @override
  void close({bool force = false}) => parent._close(_active, force: force);

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnimplementedError('FakeDohHttpClient: ${invocation.memberName}');
}

final class _FakeDohHttpClientRequest implements HttpClientRequest {
  final FakeDohHttpClient client;
  final Set<_FakeDohHttpClientRequest> active;
  @override
  final String method;
  @override
  final Uri uri;
  final FakeDohHttpScript script;
  final _body = <int>[];
  final _aborted = Completer<void>();
  late final FakeDohHttpRequestRecord record;
  bool _closed = false;

  _FakeDohHttpClientRequest(
      this.client, this.active, this.method, this.uri, this.script);

  @override
  bool followRedirects = true;
  @override
  final FakeDohHttpHeaders headers = FakeDohHttpHeaders();
  @override
  int contentLength = -1;

  @override
  void add(List<int> data) => _body.addAll(data);

  @override
  Future<HttpClientResponse> close() async {
    if (_closed) throw StateError('Request already closed');
    _closed = true;
    record = FakeDohHttpRequestRecord(
        method, uri, headers, List<int>.unmodifiable(_body));
    client.requests.add(record);
    final body = await client.reply(uri, record.body);
    return FakeDohHttpClientResponse._(
      script,
      List<int>.unmodifiable(body),
      _aborted.future,
      () => client._finished(this),
    );
  }

  @override
  void abort([Object? exception, StackTrace? stackTrace]) {
    if (!_aborted.isCompleted) {
      client.aborts++;
      if (_closed) record.aborted = true;
      _aborted.complete();
      client._finished(this);
    }
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => throw UnimplementedError(
      'FakeDohHttpClientRequest: ${invocation.memberName}');
}

/// A scripted response stream returned by [FakeDohHttpClient].
final class FakeDohHttpClientResponse extends Stream<List<int>>
    implements HttpClientResponse {
  final FakeDohHttpScript script;
  final List<int> body;
  final Future<void> aborted;
  final void Function() finished;

  FakeDohHttpClientResponse._(
      this.script, this.body, this.aborted, this.finished);

  @override
  int get statusCode => script.statusCode;

  @override
  late final FakeDohHttpHeaders headers = FakeDohHttpHeaders.response(
    contentType: script.contentType,
    age: script.age,
    contentEncoding: script.contentEncoding,
  );

  @override
  int get contentLength =>
      script.declaredContentLength ??
      (script.chunkSizes == null ? body.length : -1);

  Stream<List<int>> _stream() async* {
    try {
      if (script.delay > Duration.zero) {
        await Future<void>.delayed(script.delay);
      }
      if (script.hang) {
        await aborted;
        throw const HttpException('Request aborted');
      }
      final sizes = script.chunkSizes;
      if (sizes == null) {
        if (body.isNotEmpty) yield body;
      } else {
        var offset = 0;
        for (final size in sizes) {
          if (offset >= body.length) break;
          final end = (offset + size).clamp(offset, body.length);
          yield body.sublist(offset, end);
          offset = end;
          if (script.midBodyError case final error?) throw error;
        }
        if (offset < body.length) {
          yield body.sublist(offset);
        }
      }
      if (script.midBodyError case final error? when sizes == null) throw error;
    } finally {
      finished();
    }
  }

  @override
  StreamSubscription<List<int>> listen(
    void Function(List<int> event)? onData, {
    Function? onError,
    void Function()? onDone,
    bool? cancelOnError,
  }) =>
      _stream().listen(onData,
          onError: onError, onDone: onDone, cancelOnError: cancelOnError);

  @override
  dynamic noSuchMethod(Invocation invocation) => throw UnimplementedError(
      'FakeDohHttpClientResponse: ${invocation.memberName}');
}

/// Minimal mutable headers used by the fake request and response.
final class FakeDohHttpHeaders implements HttpHeaders {
  final Map<String, List<String>> _values = {};
  ContentType? _contentType;

  FakeDohHttpHeaders();

  FakeDohHttpHeaders.response({
    String? contentType,
    String? age,
    String? contentEncoding,
  }) {
    if (contentType != null) this.contentType = ContentType.parse(contentType);
    if (age != null) set(HttpHeaders.ageHeader, age);
    if (contentEncoding != null) {
      set(HttpHeaders.contentEncodingHeader, contentEncoding);
    }
  }

  String _key(String name) => name.toLowerCase();

  @override
  ContentType? get contentType => _contentType;

  @override
  set contentType(ContentType? value) {
    _contentType = value;
    if (value == null) {
      removeAll(HttpHeaders.contentTypeHeader);
    } else {
      set(HttpHeaders.contentTypeHeader, value.toString());
    }
  }

  @override
  void add(String name, Object value, {bool preserveHeaderCase = false}) {
    _values.putIfAbsent(_key(name), () => []).add(value.toString());
  }

  @override
  void set(String name, Object value, {bool preserveHeaderCase = false}) {
    _values[_key(name)] = [value.toString()];
  }

  @override
  void removeAll(String name) => _values.remove(_key(name));

  @override
  String? value(String name) {
    final values = this[name];
    if (values == null || values.isEmpty) return null;
    return values.join(', ');
  }

  @override
  List<String>? operator [](String name) {
    final values = _values[_key(name)];
    return values == null ? null : List.unmodifiable(values);
  }

  @override
  dynamic noSuchMethod(Invocation invocation) =>
      throw UnimplementedError('FakeDohHttpHeaders: ${invocation.memberName}');
}

List<int> wireName(String name) => [
      for (final label
          in name.split('.').where((label) => label.isNotEmpty)) ...[
        label.length,
        ...ascii.encode(label)
      ],
      0,
    ];

List<int> wireHeader({
  int id = 0x1234,
  int flags = 0x0100,
  int qd = 1,
  int an = 0,
  int ns = 0,
  int ar = 0,
}) =>
    [
      for (final value in [id, flags, qd, an, ns, ar]) ...u16(value)
    ];

List<int> u16(int value) => [value >> 8 & 0xff, value & 0xff];

List<int> wireQuestion(List<int> name, {int type = 16, int dnsClass = 1}) =>
    [...name, ...u16(type), ...u16(dnsClass)];

List<int> wireRecord(
  List<int> owner,
  int type,
  List<int> rdata, {
  int dnsClass = 1,
}) =>
    [
      ...owner,
      ...u16(type),
      ...u16(dnsClass),
      0,
      0,
      0,
      60,
      ...u16(rdata.length),
      ...rdata,
    ];

List<int> wireOpt({
  List<int> options = const [],
  int version = 0,
  List<int> owner = const [0],
}) =>
    [
      ...owner,
      ...u16(41),
      ...u16(1232),
      0,
      version,
      0x80,
      0,
      ...u16(options.length),
      ...options,
    ];

List<int> wireQuery({
  String name = 'alice.example',
  int id = 0x1234,
  bool edns = true,
  int type = 16,
}) =>
    [
      ...wireHeader(id: id, ar: edns ? 1 : 0),
      ...wireQuestion(wireName(name), type: type),
      if (edns) ...wireOpt(),
    ];

List<int> wireReply({
  String name = 'alice.example',
  int id = 0x1234,
  int flags = 0x8180,
  List<List<int>> answers = const [],
  List<List<int>> additional = const [],
}) =>
    [
      ...wireHeader(
          id: id, flags: flags, an: answers.length, ar: additional.length + 1),
      ...wireQuestion(wireName(name)),
      for (final answer in answers) ...answer,
      for (final record in additional) ...record,
      ...wireOpt(),
    ];

List<int> txtRdata(String text) => [text.length, ...ascii.encode(text)];

List<int> wireEcho(List<int> query) => [...query]
  ..[2] = 0x81
  ..[3] = 0x80;

String wireFirstLabel(List<int> message) =>
    ascii.decode(message.sublist(13, 13 + message[12]));

List<int> wireSignedQuery({int id = 0x1234, int type = 24}) => [
      ...wireHeader(id: id, ar: 2),
      ...wireQuestion(wireName('alice.example')),
      ...wireOpt(),
      ...wireRecord(
        [0],
        type,
        type == 24
            ? [
                ...u16(0),
                13,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                2,
                0,
                0,
                0,
                1,
                ...u16(7),
                ...wireName('key.example'),
                1,
                2,
                3,
                4,
              ]
            : [...wireName('hmac-sha256'), 1, 2, 3, 4],
        dnsClass: 255,
      ),
    ];
