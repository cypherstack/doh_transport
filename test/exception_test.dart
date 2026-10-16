import 'dart:async';

import 'package:doh_transport/doh_transport.dart';
import 'package:test/test.dart';

void main() {
  test('every named failure has the sealed transport root', () {
    final cause = StateError('private endpoint detail');
    final failures = <DohTransportException>[
      const DohInvalidQueryException('invalid query'),
      const DohMalformedResponseException('malformed response'),
      const DohResponseTooLargeException('too large', limitBytes: 512),
      const DohQuestionMismatchException('wrong question'),
      const DohHttpStatusException('HTTP failure', statusCode: 503),
      DohConnectionException('connection failure', cause: cause),
      const DohQueueFullException('queue full', maxQueuedRequests: 4),
      const DohRequestTimeoutException('request timeout',
          timeout: Duration(seconds: 30)),
      DohConnectionTimeoutException('connection timeout',
          timeout: const Duration(seconds: 5), cause: cause),
      const DohCancelledException('cancelled'),
    ];

    expect(failures, everyElement(isA<DohTransportException>()));
    expect(failures.map((failure) => failure.runtimeType).toSet(),
        hasLength(failures.length));
  });

  test('structured fields preserve status, limits, deadlines and reason', () {
    expect(const DohHttpStatusException('failed', statusCode: 429).statusCode,
        429);
    expect(
        const DohResponseTooLargeException('large', limitBytes: 65535)
            .limitBytes,
        65535);
    expect(
        const DohQueueFullException('full', maxQueuedRequests: 64)
            .maxQueuedRequests,
        64);
    expect(
        const DohRequestTimeoutException('late', timeout: Duration(seconds: 12))
            .timeout,
        const Duration(seconds: 12));
    expect(
        const DohCancelledException('closed',
                reason: DohCancellationReason.transportClosed)
            .reason,
        DohCancellationReason.transportClosed);
  });

  test('toString identifies leaves and renders only safe structured fields',
      () {
    final cause = StateError('resolver.example');
    expect(
        const DohHttpStatusException('request failed', statusCode: 503)
            .toString(),
        'DohHttpStatusException(statusCode: 503): request failed');
    expect(
        const DohRequestTimeoutException('timed out',
                timeout: Duration(seconds: 30))
            .toString(),
        'DohRequestTimeoutException(timeout: 0:00:30.000000): timed out');
    expect(
        const DohCancelledException('closed',
                reason: DohCancellationReason.transportClosed)
            .toString(),
        'DohCancelledException(reason: transportClosed): closed');
    final connection =
        DohConnectionException('connection failed', cause: cause);
    expect(connection.cause, same(cause));
    expect(connection.toString(), 'DohConnectionException: connection failed');
    expect(connection.toString(), isNot(contains('resolver.example')));
  });

  test('dropping any operation result cannot emit an uncaught zone error',
      () async {
    final errors = <Object>[];
    await runZonedGuarded(() async {
      DnsOperation<void>(Future<void>.error(StateError('dropped')), () {});
      await Future<void>.delayed(Duration.zero);
    }, (error, _) => errors.add(error));

    expect(errors, isEmpty);
  });
}
