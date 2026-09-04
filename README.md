# 🛡️ Mini Vulnerability Scanner

A lightweight, ethical web reconnaissance tool written in Python that checks a target website for common security misconfigurations — the kind of low-hanging fruit that real-world pentests and bug bounty recon phases flag first.

## Features

- **Security header audit** — checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Information disclosure** — flags `Server` / `X-Powered-By` banners that leak stack details
- **Cookie security** — checks session cookies for `Secure`, `HttpOnly`, and `SameSite` attributes
- **Exposed sensitive files** — probes for commonly leaked files (`.git/HEAD`, `.env`, backup files, `.htaccess`, credentials files, etc.)
- **Outdated JS library detection** — heuristic detection of old jQuery / Bootstrap / AngularJS versions with known CVEs
- **TLS/SSL check** — verifies HTTPS is enforced and reports certificate expiry
- **Reports** — export findings as JSON or a clean HTML report

## ⚠️ Legal / Ethical Notice

**Only scan systems you own or have explicit written authorization to test.**
Unauthorized scanning of third-party systems may violate laws such as the Computer Fraud and Abuse Act (US), the IT Act 2000 (India), or equivalent legislation elsewhere. This tool is for educational use, authorized security assessments, and your own applications.

## Installation

```bash
git clone https://github.com/sty3m/mini-vuln-scanner.git
cd mini-vuln-scanner
python -m pip install -r requirements.txt
```

## Usage

```bash
# Basic scan, printed to terminal
python scanner.py https://example.com

# Save as JSON report
python scanner.py https://example.com --output report.json

# Save as a styled HTML report
python scanner.py https://example.com --output report.html --format html
```

## Project Structure

```text
mini-vuln-scanner/
├── scanner.py         # Main scanner logic + CLI
├── requirements.txt   # Python dependencies
├── README.md          # Project documentation
├── LICENSE            # MIT license
├── SECURITY.md        # Security and responsible disclosure guidance
├── CONTRIBUTING.md    # Contribution guidelines
└── .gitignore         # Ignore generated/local files
```

## How it works

The scanner sends a small number of read-only HTTP GET requests to the target — it never attempts to exploit, inject, brute-force, or modify anything. Each check module returns a list of findings with a severity rating (`High` / `Medium` / `Low` / `OK` / `Info`), which are aggregated into a single report.

## Roadmap / Ideas for extension

- [ ] Add CVE lookup via the NVD API for detected library versions
- [ ] Add subdomain enumeration (crt.sh certificate transparency logs)
- [ ] Add async requests (`httpx` + `asyncio`) for faster multi-path scanning
- [ ] Add a `--rate-limit` flag to throttle requests for production targets
- [ ] Docker container for one-command usage
- [ ] Web UI wrapper (FastAPI + simple frontend)

## License

MIT — free to use, modify, and build on. Attribution appreciated.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The author is not responsible for misuse or damage caused by this tool.
