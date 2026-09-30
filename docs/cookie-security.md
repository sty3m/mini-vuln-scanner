# Cookie Security Checks

The scanner reviews cookies returned by the target and reports missing:

- `Secure` — send cookies only over HTTPS.
- `HttpOnly` — reduce access from client-side scripts.
- `SameSite` — reduce cross-site request exposure. The scanner accepts the
  standard `Lax`, `Strict`, and `None` values and reports other values as
  invalid.

Findings should be manually validated, especially for non-session cookies.
