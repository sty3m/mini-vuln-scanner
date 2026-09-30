# TLS Checks

The scanner reports whether the target uses HTTPS, when its certificate expires,
and which protocol version the local TLS client negotiated.

- Certificate expiry is reported as `OK` when more than 30 days remain,
  `Medium` when 30 days or fewer remain, and `High` after expiration.
- Negotiated TLS 1.2 and TLS 1.3 are reported as `OK`.
- SSL 3.0, TLS 1.0, and TLS 1.1 are reported as `Medium` because they are
  obsolete. The scanner recommends TLS 1.2 or newer.

The result describes one connection from the scanner's machine. It does not
prove that every client, endpoint, or network path will negotiate the same
protocol. Review the server's TLS configuration separately before making
changes.
