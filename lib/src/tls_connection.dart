import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'exceptions.dart';

/// Connects to [host], a name or address, and authenticates TLS as
/// [tlsHost], all within [timeout]. Cancelling or reaching the deadline
/// closes the socket, even mid-handshake.
///
/// [SecureSocket.secure] detaches the plain socket, after which nothing can
/// close a stalled handshake, so the handshake runs on [RawSecureSocket] and
/// [_TlsSocket] presents the result as the [Socket] that
/// [HttpClient.connectionFactory] needs.
ConnectionTask<Socket> connectTls(Object host, int port,
    {required String tlsHost,
    required SecurityContext? context,
    required Duration timeout}) {
  final result = Completer<Socket>();
  ConnectionTask<RawSocket>? tcp;
  RawSocket? plain;
  late final Timer timer;
  void fail(Object error, [StackTrace? stack]) {
    if (result.isCompleted) return;
    timer.cancel();
    tcp?.cancel();
    plain?.close();
    result.completeError(error, stack);
  }

  timer = Timer(
      timeout,
      () => fail(DohConnectionTimeoutException(
          'DNS connection deadline exceeded',
          timeout: timeout)));
  () async {
    try {
      final task = tcp = await RawSocket.startConnect(host, port);
      if (result.isCompleted) {
        task.cancel();
        return;
      }
      final socket = plain = await task.socket;
      if (result.isCompleted) {
        socket.close();
        return;
      }
      final secured =
          await RawSecureSocket.secure(socket, host: tlsHost, context: context);
      if (result.isCompleted) {
        secured.close();
        return;
      }
      timer.cancel();
      result.complete(_TlsSocket(secured));
    } catch (error, stack) {
      fail(error, stack);
    }
  }();
  return ConnectionTask.fromSocket(result.future,
      () => fail(const DohCancelledException('DNS connection cancelled')));
}

/// A [Socket] over an established [RawSecureSocket].
///
/// It ends, completing [done], when destroyed, when the raw socket fails or
/// closes, when the peer stops sending (which ends an HTTP/1.1 connection),
/// or once both directions are shut down locally. A write that is still in
/// progress at that point fails, and later writes fail with the same error.
final class _TlsSocket extends StreamView<Uint8List> implements Socket {
  final RawSecureSocket _raw;
  final StreamController<Uint8List> _incoming;
  final _ended = Completer<void>();
  late final _TlsWriter _writer = _TlsWriter(this);
  late final IOSink _sink = IOSink(_writer);
  bool _destroyed = false;
  bool _readShut = false;
  bool _writeShut = false;
  Object? _error;
  StackTrace? _errorStack;

  factory _TlsSocket(RawSecureSocket raw) =>
      _TlsSocket._(raw, StreamController<Uint8List>(sync: true));

  _TlsSocket._(this._raw, this._incoming) : super(_incoming.stream) {
    _incoming
      ..onListen = _updateReading
      ..onPause = _updateReading
      ..onResume = _updateReading
      ..onCancel = _shutRead;
    _ended.future.ignore();
    _sink.done.then((_) => _end(), onError: _end);
    _raw
      ..readEventsEnabled = false
      ..writeEventsEnabled = false
      ..listen(_event, onError: _fail, onDone: destroy);
  }

  Object get _closedError => _error ?? const SocketException('Socket closed');

  void _updateReading() {
    if (!_destroyed && !_readShut) {
      _raw.readEventsEnabled = _incoming.hasListener && !_incoming.isPaused;
    }
  }

  void _event(RawSocketEvent event) {
    if (event == RawSocketEvent.read) {
      final bytes = _raw.read();
      if (bytes != null && !_readShut && !_destroyed) _incoming.add(bytes);
    } else if (event == RawSocketEvent.write) {
      _writer.write();
    } else if (event == RawSocketEvent.readClosed) {
      destroy();
    }
  }

  void _shutRead() {
    if (_destroyed || _readShut) return;
    _readShut = true;
    _raw
      ..readEventsEnabled = false
      ..shutdown(SocketDirection.receive);
    if (_writeShut) destroy();
  }

  void _shutWrite() {
    if (_writeShut) return;
    _writeShut = true;
    _raw.shutdown(SocketDirection.send);
    if (_readShut) destroy();
  }

  /// Ends the socket with [error], which a write in progress and [done]
  /// report, as does the stream when the error came from the socket.
  void _fail(Object error, StackTrace stack, {bool fromSocket = true}) {
    if (_destroyed) return;
    _error = error;
    _errorStack = stack;
    if (fromSocket && !_readShut) _incoming.addError(error, stack);
    destroy();
  }

  void _end([Object? error, StackTrace? stack]) {
    if (_ended.isCompleted) return;
    if (error == null) {
      _ended.complete();
    } else {
      _ended.completeError(error, stack);
    }
  }

  @override
  void destroy() {
    if (_destroyed) return;
    _destroyed = true;
    if (_writer.active) _error ??= const SocketException('Socket closed');
    _raw.close();
    _incoming.close();
    _writer.finish(_error, _errorStack);
    _end(_error, _errorStack);
  }

  @override
  InternetAddress get address => _raw.address;
  @override
  int get port => _raw.port;
  @override
  InternetAddress get remoteAddress => _raw.remoteAddress;
  @override
  int get remotePort => _raw.remotePort;
  @override
  bool setOption(SocketOption option, bool enabled) =>
      _raw.setOption(option, enabled);
  @override
  Uint8List getRawOption(RawSocketOption option) => _raw.getRawOption(option);
  @override
  void setRawOption(RawSocketOption option) => _raw.setRawOption(option);

  @override
  Encoding get encoding => _sink.encoding;
  @override
  set encoding(Encoding value) => _sink.encoding = value;
  @override
  void add(List<int> data) => _sink.add(data);
  @override
  void addError(Object error, [StackTrace? stackTrace]) =>
      _sink.addError(error, stackTrace);
  @override
  Future<void> addStream(Stream<List<int>> stream) => _sink.addStream(stream);
  @override
  Future<void> flush() => _sink.flush();
  @override
  Future<void> close() => _sink.close();
  @override
  Future<void> get done => _ended.future;
  @override
  void write(Object? object) => _sink.write(object);
  @override
  void writeln([Object? object = '']) => _sink.writeln(object);
  @override
  void writeAll(Iterable<Object?> objects, [String separator = '']) =>
      _sink.writeAll(objects, separator);
  @override
  void writeCharCode(int charCode) => _sink.writeCharCode(charCode);
}

/// Writes each chunk to the raw socket, pausing its source while the TLS
/// buffer is full.
final class _TlsWriter implements StreamConsumer<List<int>> {
  final _TlsSocket socket;
  StreamSubscription<List<int>>? _source;
  Completer<void>? _done;
  List<int>? _pending;
  int _offset = 0;
  _TlsWriter(this.socket);

  bool get active => _done != null;

  @override
  Future<void> addStream(Stream<List<int>> stream) {
    if (socket._destroyed) {
      return Future.error(socket._closedError, socket._errorStack);
    }
    final done = _done = Completer<void>();
    _source = stream.listen((data) {
      _pending = data;
      _offset = 0;
      write();
    },
        onError: (Object error, StackTrace stack) =>
            socket._fail(error, stack, fromSocket: false),
        onDone: finish,
        cancelOnError: true);
    return done.future;
  }

  void write() {
    final data = _pending;
    final source = _source;
    if (data == null || source == null) return;
    try {
      _offset += socket._raw.write(data, _offset);
    } catch (error, stack) {
      socket._fail(error, stack);
      return;
    }
    if (_offset < data.length) {
      if (!source.isPaused) source.pause();
      socket._raw.writeEventsEnabled = true;
    } else {
      _pending = null;
      if (source.isPaused) source.resume();
    }
  }

  /// Ends the current stream, with [error] if the socket ended first.
  void finish([Object? error, StackTrace? stack]) {
    final done = _done;
    _source?.cancel();
    _source = null;
    _pending = null;
    _done = null;
    if (done == null) return;
    if (error == null) {
      done.complete();
    } else {
      done.completeError(error, stack);
    }
  }

  @override
  Future<void> close() {
    if (socket._destroyed) {
      return Future.error(socket._closedError, socket._errorStack);
    }
    socket._shutWrite();
    return Future.value();
  }
}
