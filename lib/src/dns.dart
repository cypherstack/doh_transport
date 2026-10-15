import 'dart:convert';
import 'dart:math';

/// Every deliberately reported failure from this package.
///
/// Callers can catch this root to handle all transport failures, or catch a
/// final leaf to preserve cancellation, timeout, HTTP, and wire distinctions.
sealed class DohTransportException implements Exception {
  final String message;
  const DohTransportException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// A name that is not an ASCII DNS name of at most 253 octets with labels of
/// letters, digits, `_` or `-`.
final class DohInvalidNameException extends DohTransportException {
  const DohInvalidNameException(super.message);
}

/// A caller-supplied wire query or request URI was unusable.
final class DohInvalidQueryException extends DohTransportException {
  const DohInvalidQueryException(super.message);
}

/// A response that does not parse or is internally inconsistent.
final class DohMalformedResponseException extends DohTransportException {
  const DohMalformedResponseException(super.message);
}

/// A response that exceeded a configured size or count bound.
final class DohResponseTooLargeException extends DohTransportException {
  final int? limitBytes;
  const DohResponseTooLargeException(super.message, {this.limitBytes});

  @override
  String toString() => limitBytes == null
      ? super.toString()
      : '$runtimeType(limitBytes: $limitBytes): $message';
}

/// A response that does not answer the question asked.
final class DohQuestionMismatchException extends DohTransportException {
  const DohQuestionMismatchException(super.message);
}

/// The resolver returned a non-success HTTP [statusCode].
final class DohHttpStatusException extends DohTransportException {
  final int statusCode;
  const DohHttpStatusException(super.message, {required this.statusCode});

  @override
  String toString() => '$runtimeType(statusCode: $statusCode): $message';
}

/// A connection, TLS handshake, proxy, or HTTP exchange failed.
///
/// [cause] is retained for programmatic diagnostics, but is deliberately not
/// included in [toString] because lower-layer errors can contain endpoints.
final class DohConnectionException extends DohTransportException {
  final Object? cause;
  const DohConnectionException(super.message, {this.cause});
}

/// A request was rejected because the bounded queue was full.
final class DohQueueFullException extends DohTransportException {
  final int maxQueuedRequests;
  const DohQueueFullException(super.message, {required this.maxQueuedRequests});

  @override
  String toString() =>
      '$runtimeType(maxQueuedRequests: $maxQueuedRequests): $message';
}

/// Why an operation was cancelled.
enum DohCancellationReason { caller, transportClosed, redirectRefused }

/// An operation cancelled by its caller or by closing its transport.
final class DohCancelledException extends DohTransportException {
  final DohCancellationReason reason;
  const DohCancelledException(super.message,
      {this.reason = DohCancellationReason.caller});

  @override
  String toString() => '$runtimeType(reason: ${reason.name}): $message';
}

/// An operation that reached its request deadline.
final class DohRequestTimeoutException extends DohTransportException {
  final Duration timeout;
  const DohRequestTimeoutException(super.message, {required this.timeout});

  @override
  String toString() => '$runtimeType(timeout: $timeout): $message';
}

/// A connection, proxy, or TLS handshake reached its deadline.
final class DohConnectionTimeoutException extends DohTransportException {
  final Duration timeout;
  final Object? cause;
  const DohConnectionTimeoutException(super.message,
      {required this.timeout, this.cause});

  @override
  String toString() => '$runtimeType(timeout: $timeout): $message';
}

final _label = RegExp(r'^[a-z0-9_-]+$');

/// The remaining lifetime of a received DNS [ttl], in seconds: zero when its
/// most significant bit is set, reduced by HTTP cache [age], and never
/// negative.
int effectiveDnsTtl(int ttl, {Duration age = Duration.zero}) {
  if (ttl < 0 || ttl > 0xffffffff) throw ArgumentError.value(ttl, 'ttl');
  if (age < Duration.zero) throw ArgumentError.value(age, 'age');
  return max(0, (ttl > 0x7fffffff ? 0 : ttl) - age.inSeconds);
}

/// Lower-cases [name], strips one trailing dot, and validates an ASCII DNS
/// name.
String normalizeDnsName(String name) {
  if (name.codeUnits.any((c) => c > 127)) {
    throw const DohInvalidNameException('Use ASCII DNS names');
  }
  final value = (name.endsWith('.') ? name.substring(0, name.length - 1) : name)
      .toLowerCase();
  if (value.isEmpty ||
      value.length > 253 ||
      !value.split('.').every((label) =>
          label.isNotEmpty && label.length <= 63 && _label.hasMatch(label))) {
    throw const DohInvalidNameException('Invalid ASCII DNS name');
  }
  return value;
}

/// A DNS resource record with a normalized owner and presentation data.
class DnsRecord {
  final String name;
  final int type;
  final int ttl;
  final String data;
  const DnsRecord({
    required this.name,
    required this.type,
    required this.ttl,
    required this.data,
  });
}

/// The octets of one TXT RRset member, with its character-strings joined.
class DnsTxtRecord {
  final String name;
  final int ttl;
  final List<int> bytes;
  DnsTxtRecord({
    required this.name,
    required this.ttl,
    required List<int> bytes,
  }) : bytes = List.unmodifiable(bytes) {
    if (this.bytes.any((byte) => byte < 0 || byte > 255)) {
      throw ArgumentError.value(bytes, 'bytes', 'TXT data must be octets');
    }
  }

  /// [bytes] decoded as UTF-8.
  String get text {
    try {
      return utf8.decode(bytes);
    } on FormatException {
      throw const DohMalformedResponseException('TXT is not UTF-8');
    }
  }
}
