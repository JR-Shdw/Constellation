"""security.py — direct middleware dispatch + helper edges (lines 49, 69,
120-121, 169-199). Calls SecurityMiddleware.dispatch() with mock requests
since the test client always runs from loopback (skipped at line 166)."""

import time

import pytest

import api.app.security as sec_mod
from api.app.security import (
    SecurityMiddleware,
    _auth_failures,
    _rate_buckets,
    _rate_check,
    auth_fail,
    is_banned,
    validate_url,
)


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, ip, auth_header=None):
        self.client = _FakeClient(ip) if ip else None
        self.headers = {}
        if auth_header is not None:
            self.headers["authorization"] = auth_header


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


def _mw():
    """Build a SecurityMiddleware with no-op app."""

    async def _app(scope, receive, send):
        pass

    return SecurityMiddleware(_app)


# ── helper edges ──────────────────────────────────────────────────────────


def test_rate_check_pops_expired_timestamps():
    """Bucket front entries past window get popped (line 49)."""
    from api.app.config import settings

    ip = "10.77.7.1"
    window = settings.rate_limit_window_seconds
    now = time.monotonic()
    # One expired + one fresh — line 48-49 must execute the pop
    _rate_buckets[ip] = [now - window - 5, now - 0.1]
    assert _rate_check(ip) is True
    # Expired entry was removed
    assert all(t > now - window for t in _rate_buckets[ip])
    _rate_buckets.pop(ip, None)


def test_auth_fail_window_reset_branch():
    """When previous failure is older than bf_window, count resets (line 69)."""
    from api.app.config import settings

    ip = "10.77.7.2"
    # Plant an old failure
    _auth_failures[ip] = (3, time.monotonic() - settings.bf_window_seconds - 60)
    auth_fail(ip)
    # New count == 1, not 4 (reset path executed)
    count, _ = _auth_failures[ip]
    assert count == 1
    _auth_failures.pop(ip, None)


def test_validate_url_urlparse_exception(monkeypatch):
    """urlparse raising → 'invalid URL format' (lines 120-121)."""

    def _boom(_):
        raise ValueError("oops")

    monkeypatch.setattr("api.app.security.urlparse", _boom)
    err = validate_url("http://example.com")
    assert err == "invalid URL format"


# ── middleware dispatch (lines 169-199) ──────────────────────────────────


@pytest.mark.anyio
async def test_dispatch_loopback_bypasses_checks():
    """Loopback IP returns immediately (line 165-166)."""
    mw = _mw()

    async def _next(_req):
        return _FakeResponse(200)

    resp = await mw.dispatch(_FakeRequest("127.0.0.1"), _next)
    assert resp.status_code == 200


@pytest.mark.anyio
async def test_dispatch_banned_returns_429():
    """Banned IP → 429 JSON response (lines 169-174)."""
    from api.app.config import settings

    ip = "203.0.113.10"
    _auth_failures[ip] = (settings.bf_max_failures, time.monotonic())

    mw = _mw()

    async def _next(_req):
        return _FakeResponse(200)

    resp = await mw.dispatch(_FakeRequest(ip), _next)
    assert resp.status_code == 429
    _auth_failures.pop(ip, None)


@pytest.mark.anyio
async def test_dispatch_rate_limited_returns_429():
    """Bucket already at limit → 429 with Retry-After (lines 177-183)."""
    from api.app.config import settings

    ip = "203.0.113.11"
    _rate_buckets[ip] = [time.monotonic()] * settings.rate_limit_requests
    _auth_failures.pop(ip, None)

    mw = _mw()

    async def _next(_req):
        return _FakeResponse(200)

    resp = await mw.dispatch(_FakeRequest(ip), _next)
    assert resp.status_code == 429
    _rate_buckets.pop(ip, None)


@pytest.mark.anyio
async def test_dispatch_tracks_bearer_auth_failure():
    """401 with Bearer token → auth_fail recorded (lines 188-192)."""
    ip = "203.0.113.12"
    _auth_failures.pop(ip, None)
    _rate_buckets.pop(ip, None)

    mw = _mw()

    async def _next(_req):
        return _FakeResponse(401)

    await mw.dispatch(
        _FakeRequest(ip, auth_header="Bearer wrong-token"), _next
    )
    assert ip in _auth_failures
    _auth_failures.pop(ip, None)
    _rate_buckets.pop(ip, None)


@pytest.mark.anyio
async def test_dispatch_clears_failure_on_success():
    """200 with Bearer token → auth_success clears prior failures (193-197)."""
    ip = "203.0.113.13"
    _auth_failures[ip] = (1, time.monotonic())
    _rate_buckets.pop(ip, None)

    mw = _mw()

    async def _next(_req):
        return _FakeResponse(200)

    await mw.dispatch(
        _FakeRequest(ip, auth_header="Bearer good-token"), _next
    )
    assert ip not in _auth_failures
    _rate_buckets.pop(ip, None)


@pytest.mark.anyio
async def test_dispatch_no_client_uses_unknown():
    """request.client is None → ip='unknown' branch (line 162)."""
    mw = _mw()

    async def _next(_req):
        return _FakeResponse(200)

    resp = await mw.dispatch(_FakeRequest(None), _next)
    assert resp.status_code == 200
    _rate_buckets.pop("unknown", None)


@pytest.mark.anyio
async def test_dispatch_401_without_bearer_no_record():
    """401 without Bearer header → no auth_fail (only Bearer is tracked)."""
    ip = "203.0.113.14"
    _auth_failures.pop(ip, None)
    _rate_buckets.pop(ip, None)

    mw = _mw()

    async def _next(_req):
        return _FakeResponse(401)

    await mw.dispatch(_FakeRequest(ip), _next)
    # No bearer header → no failure tracking
    assert ip not in _auth_failures
    _rate_buckets.pop(ip, None)


def test_is_banned_active(monkeypatch):
    """Active ban returns True (line 91)."""
    from api.app.config import settings

    ip = "203.0.113.20"
    _auth_failures[ip] = (settings.bf_max_failures + 1, time.monotonic())
    assert is_banned(ip) is True
    _auth_failures.pop(ip, None)
