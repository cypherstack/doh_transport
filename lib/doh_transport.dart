/// Bounded DNS-over-HTTPS transport contracts, records, errors, and wire
/// helpers.
library;

export 'src/dns.dart';
export 'src/transport.dart';
export 'src/wire.dart'
    show
        adjustDnsWireTtls,
        padDnsWireQuery,
        validateDnsWireResponse,
        isUsableDohEndpoint;
