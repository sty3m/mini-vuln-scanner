# Security Headers Reference

A quick reference for the headers checked by Mini Vulnerability Scanner.

- Strict-Transport-Security: enforce HTTPS.
- Content-Security-Policy: reduce script and injection risk.
- X-Frame-Options: reduce clickjacking risk.
- X-Content-Type-Options: prevent MIME sniffing.
- Referrer-Policy: limit referrer data leakage.
- Permissions-Policy: restrict browser capabilities.

The X-Content-Type-Options check expects the value `nosniff`; merely returning
the header with another value does not enable the protection. The
X-Frame-Options check accepts `DENY` or `SAMEORIGIN`. Other headers are
currently checked for presence, so a reported `OK` does not validate every
directive or policy choice.
