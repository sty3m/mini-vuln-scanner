# Safe Scanning Practices

Use the scanner only against systems you own or have explicit authorization to test.

Keep scans low impact, review findings manually, and retain reports for remediation tracking. Avoid brute force, exploitation, destructive requests, or attempts to bypass access controls.

## Request volume

A scan currently makes three page requests (for headers, cookies, and library
references), then one request for each of the 16 configured sensitive paths. An
HTTPS target also receives a separate TLS connection. Redirect chains can add
requests. The `--timeout` option limits how long an individual request or TLS
connection waits; it does not reduce the number of checks or implement
rate-limiting.
