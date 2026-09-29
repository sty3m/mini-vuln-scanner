from datetime import datetime, timezone

import pytest

from scanner import normalize_url, summarize, utc_timestamp, version_tuple


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "https://example.com"),
        ("http://example.com/path/", "http://example.com/path"),
        ("  https://example.com  ", "https://example.com"),
        ("localhost:5000", "https://localhost:5000"),
    ],
)
def test_normalize_url_accepts_http_targets(value, expected):
    assert normalize_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "ftp://example.com",
        "https:///missing-host",
        "https://user:secret@example.com",
        "https://example.com:99999",
        "https://[invalid",
    ],
)
def test_normalize_url_rejects_invalid_or_unsafe_targets(value):
    with pytest.raises(ValueError):
        normalize_url(value)


def test_utc_timestamp_is_iso8601_with_one_utc_marker():
    value = utc_timestamp()

    assert value.endswith("Z")
    assert "+00:00Z" not in value
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    assert parsed.tzinfo == timezone.utc


def test_summarize_counts_findings_by_severity():
    findings = [
        {"severity": "High"},
        {"severity": "OK"},
        {"severity": "High"},
        {},
    ]

    assert summarize(findings) == {"High": 2, "OK": 1, "Info": 1}


def test_version_tuple_parses_major_minor_patch():
    assert version_tuple("3.4.1") == (3, 4, 1)


class FakeResponse:
    def __init__(self, url, headers=None, cookies=None):
        self.url = url
        self.headers = headers or {}
        self.cookies = cookies or []


class FakeSession:
    def __init__(self, response):
        self.response = response

    def get(self, *args, **kwargs):
        return self.response


def test_security_headers_skip_hsts_for_http_response():
    from scanner import check_security_headers

    findings = check_security_headers(
        "http://example.test", FakeSession(FakeResponse("http://example.test"))
    )

    assert not any(
        finding.get("item") == "Strict-Transport-Security" for finding in findings
    )


def test_security_headers_report_missing_hsts_for_https_response():
    from scanner import check_security_headers

    findings = check_security_headers(
        "https://example.test", FakeSession(FakeResponse("https://example.test"))
    )

    hsts = next(
        finding for finding in findings
        if finding.get("item") == "Strict-Transport-Security"
    )
    assert hsts["severity"] == "High"


def test_security_headers_check_final_url_after_redirect():
    from scanner import check_security_headers

    response = FakeResponse(
        "https://example.test",
        headers={"Strict-Transport-Security": "max-age=31536000"},
    )
    findings = check_security_headers(
        "http://example.test", FakeSession(response)
    )

    hsts = next(
        finding for finding in findings
        if finding.get("item") == "Strict-Transport-Security"
    )
    assert hsts["severity"] == "OK"


def test_cookie_check_reports_missing_security_attributes():
    import requests
    from scanner import check_cookies

    jar = requests.cookies.RequestsCookieJar()
    jar.set_cookie(requests.cookies.create_cookie("session", "value"))
    findings = check_cookies(
        "https://example.test", FakeSession(FakeResponse("https://example.test", cookies=jar))
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "Medium"
    assert "Secure" in findings[0]["detail"]
    assert "HttpOnly" in findings[0]["detail"]
    assert "SameSite" in findings[0]["detail"]


def test_cookie_check_accepts_all_security_attributes():
    import requests
    from scanner import check_cookies

    jar = requests.cookies.RequestsCookieJar()
    cookie = requests.cookies.create_cookie(
        "session",
        "value",
        secure=True,
        rest={"HttpOnly": None, "SameSite": "Strict"},
    )
    jar.set_cookie(cookie)
    findings = check_cookies(
        "https://example.test", FakeSession(FakeResponse("https://example.test", cookies=jar))
    )

    assert findings[0]["severity"] == "OK"
