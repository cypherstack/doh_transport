import 'dart:convert';
import 'dart:math';

/// Every DNS failure reported by the transport, resolver, or validator
/// packages.
abstract base class DnsException implements Exception {
  final String message;
  const DnsException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// A name that is not an ASCII DNS name of at most 253 octets with labels of
/// letters, digits, `_` or `-`.
final class DnsInvalidNameException extends DnsException {
  const DnsInvalidNameException(super.message);
}

/// A caller-supplied wire query or request URI was unusable.
final class DnsInvalidQueryException extends DnsException {
  const DnsInvalidQueryException(super.message);
}

/// A response that does not parse or is internally inconsistent.
final class DnsMalformedResponseException extends DnsException {
  const DnsMalformedResponseException(super.message);
}

/// A response that exceeded a configured size or count bound.
final class DnsResponseTooLargeException extends DnsException {
  const DnsResponseTooLargeException(super.message);
}

/// A response that does not answer the question asked.
final class DnsQuestionMismatchException extends DnsException {
  const DnsQuestionMismatchException(super.message);
}

/// The HTTPS exchange failed; [httpStatus] is set for a non-200 response.
final class DnsTransportException extends DnsException {
  final int? httpStatus;
  const DnsTransportException(super.message, {this.httpStatus});
}

/// An operation cancelled by its caller or by closing its transport.
final class DnsCancelledException extends DnsException {
  const DnsCancelledException(super.message);
}

/// An operation that reached its own deadline. Connection establishment
/// timeouts are reported as [DnsTransportException].
final class DnsTimeoutException extends DnsException {
  const DnsTimeoutException(super.message);
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
    throw const DnsInvalidNameException('Use ASCII DNS names');
  }
  final value = (name.endsWith('.') ? name.substring(0, name.length - 1) : name)
      .toLowerCase();
  if (value.isEmpty ||
      value.length > 253 ||
      !value.split('.').every((label) =>
          label.isNotEmpty && label.length <= 63 && _label.hasMatch(label))) {
    throw const DnsInvalidNameException('Invalid ASCII DNS name');
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
      throw const DnsMalformedResponseException('TXT is not UTF-8');
    }
  }
}
