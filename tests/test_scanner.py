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
