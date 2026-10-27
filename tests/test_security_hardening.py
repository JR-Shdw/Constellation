"""Security hardening — CSV formula injection + configurable rate limit + BF ban.

Unit-level tests that don't require Postgres. They verify:
- CSV sanitization prefixes `'` on cells starting with formula trigger chars
- Rate limit and brute-force thresholds come from settings (not hard-coded)
"""

import pytest

# CSV formula injection


def test_sanitize_csv_cell_prefixes_equals():
    from api.app.routes.export import _sanitize_csv_cell

    assert _sanitize_csv_cell("=HYPERLINK()") == "'=HYPERLINK()"


def test_sanitize_csv_cell_prefixes_plus_minus_at():
    from api.app.routes.export import _sanitize_csv_cell

    assert _sanitize_csv_cell("+attack") == "'+attack"
    assert _sanitize_csv_cell("-cmd") == "'-cmd"
    assert _sanitize_csv_cell("@sum") == "'@sum"


def test_sanitize_csv_cell_prefixes_tab_cr():
    from api.app.routes.export import _sanitize_csv_cell

    assert _sanitize_csv_cell("\tbad") == "'\tbad"
    assert _sanitize_csv_cell("\rbad") == "'\rbad"


def test_sanitize_csv_cell_passthrough_safe_strings():
    from api.app.routes.export import _sanitize_csv_cell

    assert _sanitize_csv_cell("hostname") == "hostname"
    assert _sanitize_csv_cell("CVE-2024-1234") == "CVE-2024-1234"
    assert _sanitize_csv_cell("") == ""


def test_sanitize_csv_cell_passthrough_non_strings():
    from api.app.routes.export import _sanitize_csv_cell

    assert _sanitize_csv_cell(42) == 42
    assert _sanitize_csv_cell(None) is None
    assert _sanitize_csv_cell(True) is True


@pytest.mark.anyio
async def test_csv_response_sanitizes_dangerous_cells():
    """Full round-trip: a row with a malicious hostname is safely escaped."""
    from api.app.routes.export import _csv_response

    rows = [{"hostname": "=HYPERLINK(1)", "cves": 5}]
    resp = _csv_response(rows, "test.csv")
    chunks = [c async for c in resp.body_iterator]
    body = "".join(c if isinstance(c, str) else c.decode() for c in chunks)
    assert "'=HYPERLINK(1)" in body
    assert resp.media_type == "text/csv"


# Rate limiting & brute-force — configurable via settings


def test_rate_limit_reads_settings(monkeypatch):
    """_rate_check respects settings.rate_limit_requests."""
    from api.app import security
    from api.app.config import settings

    # Reset bucket state for a clean test
    security._rate_buckets.clear()

    monkeypatch.setattr(settings, "rate_limit_requests", 3)
    monkeypatch.setattr(settings, "rate_limit_window_seconds", 60)

    ip = "10.99.99.1"
    assert security._rate_check(ip) is True
    assert security._rate_check(ip) is True
    assert security._rate_check(ip) is True
    # 4th request in the window → blocked
    assert security._rate_check(ip) is False


def test_brute_force_reads_settings(monkeypatch):
    """is_banned triggers at settings.bf_max_failures."""
    from api.app import security
    from api.app.config import settings

    security._auth_failures.clear()

    monkeypatch.setattr(settings, "bf_max_failures", 3)
    monkeypatch.setattr(settings, "bf_window_seconds", 300)
    monkeypatch.setattr(settings, "bf_ban_seconds", 300)

    ip = "10.99.99.2"
    security.auth_fail(ip)
    security.auth_fail(ip)
    assert security.is_banned(ip) is False
    security.auth_fail(ip)
    assert security.is_banned(ip) is True


def test_auth_success_clears_counter(monkeypatch):
    """A successful auth resets the failure counter."""
    from api.app import security
    from api.app.config import settings

    security._auth_failures.clear()
    monkeypatch.setattr(settings, "bf_max_failures", 3)

    ip = "10.99.99.3"
    security.auth_fail(ip)
    security.auth_fail(ip)
    security.auth_success(ip)
    # Counter cleared — can fail again without tripping the ban
    security.auth_fail(ip)
    security.auth_fail(ip)
    assert security.is_banned(ip) is False


def test_loopback_skips_rate_limit_in_middleware():
    """Loopback IPs (scheduler, internal health checks) bypass the middleware."""
    from api.app.security import _LOOPBACK

    assert "127.0.0.1" in _LOOPBACK
    assert "::1" in _LOOPBACK


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
