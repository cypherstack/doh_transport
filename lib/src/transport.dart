import 'dart:async';

import 'dns.dart';

/// A started request. Starting never throws: every failure completes [result]
/// with a [DohTransportException], and an unawaited [result] never raises an
/// uncaught error.
class DnsOperation<T> {
  final Future<T> result;

  /// Fails an unfinished operation and releases its work. Repeated calls are
  /// safe.
  final void Function() cancel;
  DnsOperation(this.result, this.cancel) {
    result.ignore();
  }

  /// The error is reported only to listeners of [result]; dropping it is safe.
  DnsOperation.failed(DohTransportException error)
      : this(Future<T>.error(error), _noop);
}

void _noop() {}

/// A complete HTTPS response from a DoH resolver.
class DohHttpResponse {
  final int statusCode;
  final List<int> body;

  /// Time the response spent in HTTP caches, from its `Age` header.
  final Duration age;
  DohHttpResponse(this.statusCode, List<int> body, {this.age = Duration.zero})
      : body = List.unmodifiable(body) {
    if (age < Duration.zero) throw ArgumentError.value(age, 'age');
  }
}

/// Sends bounded DoH JSON GET requests.
///
/// Implementations deliver failures through [DnsOperation.result] and make
/// cancellation idempotent.
abstract interface class DohTransport {
  DnsOperation<DohHttpResponse> start(Uri uri, {required int maxResponseBytes});
}

/// Sends bounded RFC 8484 wire-format queries.
abstract interface class DohWireTransport {
  /// Sends [query]. With [preserveMessage], its bytes and the response bytes
  /// are kept exactly as exchanged for transaction signatures such as SIG(0).
  DnsOperation<DohHttpResponse> startWire(
    Uri uri,
    List<int> query, {
    required int maxResponseBytes,
    bool preserveMessage = false,
  });
}
