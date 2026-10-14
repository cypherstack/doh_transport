# doh_transport

DNS-over-HTTPS transport for Dart: bounded JSON and RFC 8484 wire exchanges,
direct or through SOCKS5, plus DNS wire helpers and a typed failure hierarchy.

## Usage

```dart
import 'package:doh_transport/doh_transport_io.dart';

final transport = IoDohTransport();
try {
  final response = await transport
      .startWire(endpoint, query, maxResponseBytes: 65535)
      .result;
  final aged = adjustDnsWireTtls(response.body, age: response.age);
} on DnsException catch (error) {
  print(error);
} finally {
  await transport.close();
}
```

`doh_transport.dart` is platform-neutral: the `DohTransport` and
`DohWireTransport` interfaces, `DnsOperation`, `DohHttpResponse`, the record
types, `DnsException` and its leaves, and the wire helpers.
`doh_transport_io.dart` adds `IoDohTransport` and `SocksProxy` on `dart:io`.

## Trust model

`IoDohTransport` verifies the endpoint certificate, refuses redirects, bounds
response size and time, and never falls back from a configured proxy to a
direct connection. `validateDnsWireResponse` checks framing and that the reply
answers the query sent. Nothing here validates DNSSEC: the resolver sees every
query name and type and may answer as it likes. Without a proxy it also sees
your address.

Every failure is a `DnsException` leaf delivered through `DnsOperation.result`;
`start` and `startWire` never throw. `DnsException` is an open base class, so
resolver packages add their own leaves.

## Configuration

`IoDohTransport` options:

- `proxy`: a `SocksProxy` with a numeric address. `SocksCredentials.isolation`
  gives Tor stream isolation.
- `destination`: connect every request to this address, directly or through
  the proxy, so the endpoint host is never resolved. TLS still authenticates
  the URI host, so the address must serve its certificate.
- `reuseConnections`: share one connection per origin for wire queries. On by
  default without a proxy, off with one, where a shared connection lets the
  resolver link lookups. Pass `true` when the transport already represents one
  isolated lookup. JSON requests never share connections.
- `connectionTimeout` 5 s; `requestTimeout` 30 s per operation once it leaves
  the queue; `idleTimeout` 5 s; `maxConcurrentRequests` 8;
  `maxQueuedRequests` 64; `padQueries` true (RFC 8467 padding).
- `securityContext` for custom trust roots. `httpClientFactory` is for tests
  and bypasses the TLS and connection guarantees.

Wire query IDs are rewritten per connection and restored in the reply. Signed
(SIG(0), TSIG) and `preserveMessage` exchanges keep their exact bytes.

## Development

`package:doh_transport/testing.dart` has a socket-free `FakeDohHttpClient`
(pass its `create` as `httpClientFactory`) and DNS wire builders. It does not
depend on `package:test`.

```
dart tool/check.dart         # format, analyze, test, publish --dry-run
dart test -x integration     # skip the loopback socket tests
DOH_LIVE_TESTS=1 dart test   # also query public resolvers
```

## License

MIT; see `LICENSE`. `test/support/LICENSE` covers the test support files.
