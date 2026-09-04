#!/usr/bin/env python3
"""
Mini Vulnerability Scanner
---------------------------
A lightweight, ethical web reconnaissance tool that checks a target URL for:
  1. Missing / misconfigured security headers
  2. Outdated or vulnerable JavaScript libraries (via CDN heuristics)
  3. Commonly exposed sensitive files (.git, .env, backup files, etc.)
  4. Basic TLS/SSL certificate info
  5. Cookie security flags

IMPORTANT / LEGAL NOTICE:
Only run this against systems you own or have explicit written permission
to test. Unauthorized scanning of third-party systems may violate laws
such as the Computer Fraud and Abuse Act (US), the IT Act 2000 (India),
or equivalent legislation in your jurisdiction.

Usage:
    python scanner.py https://example.com
    python scanner.py https://example.com --output report.json
    python scanner.py https://example.com --output report.pdf --format pdf
"""

import argparse
import json
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

# --------------------------------------------------------------------------- #
# Config: what we check for
# --------------------------------------------------------------------------- #

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "advice": "Add HSTS to force HTTPS and prevent downgrade/MITM attacks.",
    },
    "Content-Security-Policy": {
        "severity": "High",
        "advice": "Add a CSP to mitigate XSS and data-injection attacks.",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "advice": "Add X-Frame-Options (or frame-ancestors in CSP) to prevent clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "advice": "Add 'nosniff' to prevent MIME-type sniffing attacks.",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "advice": "Add a Referrer-Policy to limit information leakage via the Referer header.",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "advice": "Add a Permissions-Policy to restrict access to sensitive browser features.",
    },
}

SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config", ".env", ".env.local", ".htaccess",
    "config.php.bak", "wp-config.php.bak", "backup.zip", "backup.sql",
    "database.sql", ".DS_Store", "id_rsa", ".ssh/id_rsa",
    "docker-compose.yml", ".aws/credentials", "web.config", "phpinfo.php",
]

JS_LIBRARY_PATTERNS = {
    "jquery": {
        "regex": r"jquery[-.](\d+\.\d+\.\d+)",
        "vulnerable_below": (3, 5, 0),
        "note": "Older jQuery versions (<3.5.0) have known XSS issues (e.g. CVE-2020-11022/11023).",
    },
    "bootstrap": {
        "regex": r"bootstrap[-.](\d+\.\d+\.\d+)",
        "vulnerable_below": (4, 3, 1),
        "note": "Older Bootstrap versions (<4.3.1) have known XSS issues in tooltip/popover.",
    },
    "angular": {
        "regex": r"angular[.-](\d+\.\d+\.\d+)",
        "vulnerable_below": (1, 8, 0),
        "note": "AngularJS 1.x versions before 1.8.0 have known sandbox-bypass XSS issues.",
    },
}

REQUEST_TIMEOUT = 8
USER_AGENT = "MiniVulnScanner/1.0 (+educational-use)"


def normalize_url(url: str) -> str:
    if not re.match(r"^https?://", url):
        url = "https://" + url
    return url.rstrip("/")


def version_tuple(v: str):
    return tuple(int(x) for x in v.split(".")[:3])


def colored_severity(sev: str) -> str:
    colors = {"High": Fore.RED, "Medium": Fore.YELLOW, "Low": Fore.CYAN, "Info": Fore.WHITE, "OK": Fore.GREEN}
    return f"{colors.get(sev, '')}{sev}{Style.RESET_ALL}"


def check_security_headers(url: str, session: requests.Session) -> list:
    findings = []
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except requests.RequestException as e:
        return [{"check": "Security Headers", "severity": "Error", "detail": str(e)}]
    headers = resp.headers
    for header, meta in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({"check": "Security Headers", "item": header, "severity": meta["severity"], "detail": f"Missing header: {header}", "advice": meta["advice"]})
        else:
            findings.append({"check": "Security Headers", "item": header, "severity": "OK", "detail": f"{header}: {headers[header]}"})
    for banner_header in ("Server", "X-Powered-By"):
        if banner_header in headers:
            findings.append({"check": "Information Disclosure", "item": banner_header, "severity": "Low", "detail": f"{banner_header} header reveals: {headers[banner_header]}", "advice": f"Consider suppressing the {banner_header} header to reduce fingerprinting."})
    return findings


def check_cookies(url: str, session: requests.Session) -> list:
    findings = []
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException:
        return findings
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing 'Secure' flag")
        httponly = cookie._rest.get("HttpOnly") if hasattr(cookie, "_rest") else None
        if httponly is None:
            issues.append("missing 'HttpOnly' flag")
        samesite = cookie._rest.get("SameSite") if hasattr(cookie, "_rest") else None
        if samesite is None:
            issues.append("missing 'SameSite' attribute")
        if issues:
            findings.append({"check": "Cookie Security", "item": cookie.name, "severity": "Medium", "detail": f"Cookie '{cookie.name}' issues: {', '.join(issues)}", "advice": "Set Secure, HttpOnly, and SameSite attributes on all session cookies."})
        else:
            findings.append({"check": "Cookie Security", "item": cookie.name, "severity": "OK", "detail": f"Cookie '{cookie.name}' has Secure, HttpOnly, and SameSite set."})
    return findings


def check_sensitive_paths(url: str, session: requests.Session) -> list:
    findings = []
    for path in SENSITIVE_PATHS:
        target = urljoin(url + "/", path)
        try:
            resp = session.get(target, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            findings.append({"check": "Exposed Sensitive Files", "item": path, "severity": "High", "detail": f"Publicly accessible: {target} (HTTP {resp.status_code})", "advice": "Remove or block public access to this file immediately."})
    return findings


def check_js_libraries(url: str, session: requests.Session) -> list:
    findings = []
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT)
        html = resp.text
    except requests.RequestException:
        return findings
    for lib, meta in JS_LIBRARY_PATTERNS.items():
        match = re.search(meta["regex"], html, re.IGNORECASE)
        if match:
            version = match.group(1)
            try:
                if version_tuple(version) < meta["vulnerable_below"]:
                    findings.append({"check": "Outdated JS Library", "item": lib, "severity": "Medium", "detail": f"Detected {lib} v{version} (potentially outdated)", "advice": meta["note"]})
                else:
                    findings.append({"check": "Outdated JS Library", "item": lib, "severity": "OK", "detail": f"Detected {lib} v{version} (looks current)"})
            except ValueError:
                pass
    return findings


def check_tls(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    if parsed.scheme != "https":
        findings.append({"check": "TLS/SSL", "severity": "High", "detail": "Site is not served over HTTPS.", "advice": "Enable HTTPS with a valid TLS certificate for all traffic."})
        return findings
    host = parsed.hostname
    port = parsed.port or 443
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=REQUEST_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days
                severity = "OK" if days_left > 30 else "Medium" if days_left > 0 else "High"
                findings.append({"check": "TLS/SSL", "item": "Certificate Expiry", "severity": severity, "detail": f"Certificate expires in {days_left} days ({cert['notAfter']})"})
                findings.append({"check": "TLS/SSL", "item": "Protocol", "severity": "Info", "detail": f"Negotiated protocol: {ssock.version()}"})
    except Exception as e:
        findings.append({"check": "TLS/SSL", "severity": "Error", "detail": f"Could not verify TLS configuration: {e}"})
    return findings


def run_scan(url: str) -> dict:
    url = normalize_url(url)
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    print(f"\n{Fore.CYAN}Scanning target: {url}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Started at: {datetime.now(timezone.utc).isoformat()}Z{Style.RESET_ALL}\n")
    all_findings = []
    checks = [("Security Headers", check_security_headers, (url, session)), ("Cookie Security", check_cookies, (url, session)), ("Exposed Sensitive Files", check_sensitive_paths, (url, session)), ("Outdated JS Libraries", check_js_libraries, (url, session)), ("TLS/SSL Configuration", check_tls, (url,))]
    for label, func, args in checks:
        print(f"{Fore.MAGENTA}[*] Running: {label}...{Style.RESET_ALL}")
        results = func(*args)
        for f in results:
            sev = f.get("severity", "Info")
            print(f"    [{colored_severity(sev)}] {f.get('item', f['check'])}: {f['detail']}")
        all_findings.extend(results)
    summary = summarize(all_findings)
    print(f"\n{Fore.CYAN}--- Summary ---{Style.RESET_ALL}")
    for sev in ("High", "Medium", "Low", "OK", "Info", "Error"):
        if summary.get(sev):
            print(f"  {colored_severity(sev)}: {summary[sev]}")
    return {"target": url, "scanned_at": datetime.now(timezone.utc).isoformat() + "Z", "summary": summary, "findings": all_findings}


def summarize(findings: list) -> dict:
    summary = {}
    for f in findings:
        sev = f.get("severity", "Info")
        summary[sev] = summary.get(sev, 0) + 1
    return summary


def save_json(report: dict, path: str):
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n{Fore.GREEN}Report saved to {path}{Style.RESET_ALL}")


def save_html(report: dict, path: str):
    rows = ""
    for f in report["findings"]:
        rows += ("<tr>" f"<td>{f['check']}</td>" f"<td>{f.get('item', '-')}</td>" f"<td class='sev-{f.get('severity','Info').lower()}'>{f.get('severity','Info')}</td>" f"<td>{f['detail']}</td>" f"<td>{f.get('advice', '')}</td>" "</tr>")
    html = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Vulnerability Scan Report - {report['target']}</title><style>body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 2rem; background:#0f1117; color:#e6e6e6; }} h1 {{ color:#fff; }} table {{ width:100%; border-collapse: collapse; margin-top:1rem; }} th, td {{ padding: 8px 12px; border-bottom: 1px solid #333; text-align:left; font-size:14px;}} th {{ background:#1c1f2b; }} .sev-high {{ color:#ff5c5c; font-weight:bold; }} .sev-medium {{ color:#ffc857; font-weight:bold; }} .sev-low {{ color:#5cc8ff; }} .sev-ok {{ color:#5cff8f; }} .sev-info {{ color:#aaa; }} .sev-error {{ color:#ff8a5c; }} .meta {{ color:#999; font-size: 13px; }}</style></head><body><h1>Vulnerability Scan Report</h1><p class="meta">Target: <strong>{report['target']}</strong><br>Scanned at: {report['scanned_at']}</p><p class="meta">Summary: {report['summary']}</p><table><tr><th>Check</th><th>Item</th><th>Severity</th><th>Detail</th><th>Advice</th></tr>{rows}</table></body></html>"""
    with open(path, "w") as f:
        f.write(html)
    print(f"\n{Fore.GREEN}Report saved to {path}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="Mini Vulnerability Scanner - ethical web recon tool. Only scan systems you own or are authorized to test.")
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--output", "-o", help="Path to save the report file")
    parser.add_argument("--format", "-f", choices=["json", "html"], default="json", help="Report format (default: json)")
    args = parser.parse_args()
    report = run_scan(args.url)
    if args.output:
        if args.format == "html":
            save_html(report, args.output)
        else:
            save_json(report, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(1)
