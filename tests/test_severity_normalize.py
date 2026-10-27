"""normalize_severity — vendor mapping + CHECK-safe clamping."""

import pytest

from api.app.utils.severity import normalize_severity


@pytest.mark.parametrize(
    "raw,expected",
    [
        # CVSS / Trivy / Wazuh pass-through (case-insensitive)
        ("CRITICAL", "critical"),
        ("High", "high"),
        ("medium", "medium"),
        ("LOW", "low"),
        ("Unknown", "unknown"),
        # Red Hat / Microsoft / SUSE 4-tier
        ("Important", "high"),
        ("Moderate", "medium"),
        # Ubuntu / Debian
        ("negligible", "low"),
        ("unimportant", "low"),
        # misc
        ("info", "low"),
        ("informational", "low"),
        ("none", "unknown"),
        ("untriaged", "unknown"),
        # empty / missing / junk -> unknown
        ("", "unknown"),
        ("  ", "unknown"),
        (None, "unknown"),
        ("totally-made-up", "unknown"),
    ],
)
def test_canonical_mapping(raw, expected):
    assert normalize_severity(raw) == expected


def test_important_is_high_not_critical():
    # Misleading word: Important is the vendors' High band, not Critical.
    assert normalize_severity("important") == "high"
    assert normalize_severity("critical") == "critical"


def test_allow_unknown_false_uses_fallback():
    # For columns whose CHECK forbids 'unknown' (drift_reports, secret_rules)
    assert normalize_severity("", allow_unknown=False, fallback="medium") == "medium"
    assert normalize_severity(None, allow_unknown=False, fallback="high") == "high"
    assert normalize_severity("untriaged", allow_unknown=False, fallback="low") == "low"
    # A recognized real level is unaffected by the fallback
    assert (
        normalize_severity("important", allow_unknown=False, fallback="medium")
        == "high"
    )
