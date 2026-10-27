"""Resync helpers — _read_result / _wait_for_result / _write_trigger edges."""

import pytest


def test_read_result_missing(tmp_path, monkeypatch):
    """Missing result file → returns None (no exception)."""
    import api.app.routes.resync as rm

    monkeypatch.setattr(rm, "TRIGGER_DIR", tmp_path)
    assert rm._read_result("nonexistent") is None


def test_read_result_oserror_swallowed(tmp_path, monkeypatch):
    """read_text raising OSError is swallowed → None."""
    import api.app.routes.resync as rm

    monkeypatch.setattr(rm, "TRIGGER_DIR", tmp_path)
    # Create a file, then patch Path.read_text to raise OSError
    result = tmp_path / "sync_wazuh.result"
    result.write_text("ok")

    real_read = type(result).read_text

    def _boom(self, *a, **kw):
        raise OSError("disk read fail")

    monkeypatch.setattr(type(result), "read_text", _boom)
    try:
        assert rm._read_result("sync_wazuh") is None
    finally:
        monkeypatch.setattr(type(result), "read_text", real_read)


def test_write_trigger_oserror_returns_false(tmp_path, monkeypatch):
    """Write failure (read-only dir) → returns False, no raise."""
    import api.app.routes.resync as rm

    monkeypatch.setattr(rm, "TRIGGER_DIR", tmp_path / "nonexistent-readonly")

    from pathlib import Path

    real_write = Path.write_text

    def _boom(self, *a, **kw):
        raise OSError("cannot write")

    monkeypatch.setattr(Path, "write_text", _boom)
    try:
        assert rm._write_trigger("sync_wazuh") is False
    finally:
        monkeypatch.setattr(Path, "write_text", real_write)


@pytest.mark.anyio
async def test_wait_for_result_returns_val(tmp_path, monkeypatch):
    """Existing result file → returns value and deletes file."""
    import api.app.routes.resync as rm

    monkeypatch.setattr(rm, "TRIGGER_DIR", tmp_path)
    (tmp_path / "sync_wazuh.result").write_text("ok\n")

    val = await rm._wait_for_result("sync_wazuh", timeout=4)
    assert val == "ok"
    assert not (tmp_path / "sync_wazuh.result").exists()


@pytest.mark.anyio
async def test_wait_for_result_timeout(tmp_path, monkeypatch):
    """No result file appears within timeout → None."""
    import api.app.routes.resync as rm

    monkeypatch.setattr(rm, "TRIGGER_DIR", tmp_path)

    async def _nosleep(*a, **kw):
        return None

    monkeypatch.setattr(rm.asyncio, "sleep", _nosleep)
    val = await rm._wait_for_result("never", timeout=4)
    assert val is None


@pytest.mark.anyio
async def test_resync_wazuh_trigger_write_failure(client, auth, monkeypatch):
    """_write_trigger False → /resync/wazuh returns error status."""
    import api.app.routes.resync as rm

    monkeypatch.setattr(rm, "_write_trigger", lambda *a, **k: False)
    r = await client.post("/api/v1/resync/wazuh", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_resync_wazuh_error_result(client, auth, monkeypatch):
    """_wait_for_result returning 'error:...' → status=warning."""
    import api.app.routes.resync as rm

    async def _err(*a, **kw):
        return "error: worker died"

    monkeypatch.setattr(rm, "_wait_for_result", _err)
    monkeypatch.setattr(rm, "_write_trigger", lambda *a, **k: True)
    r = await client.post("/api/v1/resync/wazuh", headers=auth)
    assert r.status_code == 200
    assert r.json()["status"] == "warning"


@pytest.mark.anyio
async def test_resync_wazuh_success_result(client, auth, monkeypatch):
    """_wait_for_result returning plain 'ok' → status=ok completed successfully."""
    import api.app.routes.resync as rm

    async def _ok(*a, **kw):
        return "ok"

    monkeypatch.setattr(rm, "_wait_for_result", _ok)
    monkeypatch.setattr(rm, "_write_trigger", lambda *a, **k: True)
    r = await client.post("/api/v1/resync/wazuh", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "successfully" in data["detail"]


@pytest.mark.anyio
async def test_resync_opencve_trigger_write_failure(client, auth, monkeypatch):
    """_write_trigger False → /resync/opencve returns error."""
    import api.app.routes.resync as rm

    monkeypatch.setattr(rm, "_write_trigger", lambda *a, **k: False)
    r = await client.post(
        "/api/v1/resync/opencve", json={"hours": 24}, headers=auth
    )
    assert r.status_code == 200
    assert r.json()["status"] == "error"


@pytest.mark.anyio
async def test_resync_opencve_error_result(client, auth, monkeypatch):
    """_wait_for_result 'error:...' → status=warning on opencve."""
    import api.app.routes.resync as rm

    async def _err(*a, **kw):
        return "error: boom"

    monkeypatch.setattr(rm, "_wait_for_result", _err)
    monkeypatch.setattr(rm, "_write_trigger", lambda *a, **k: True)
    r = await client.post(
        "/api/v1/resync/opencve", json={"hours": 12}, headers=auth
    )
    assert r.status_code == 200
    assert r.json()["status"] == "warning"


@pytest.mark.anyio
async def test_resync_opencve_success_result(client, auth, monkeypatch):
    """Successful opencve result → status=ok with hours window detail."""
    import api.app.routes.resync as rm

    async def _ok(*a, **kw):
        return "ok"

    monkeypatch.setattr(rm, "_wait_for_result", _ok)
    monkeypatch.setattr(rm, "_write_trigger", lambda *a, **k: True)
    r = await client.post(
        "/api/v1/resync/opencve", json={"hours": 6}, headers=auth
    )
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "6h" in data["detail"]


def test_ensure_trigger_dir_oserror_swallowed(tmp_path, monkeypatch):
    """_ensure_trigger_dir must swallow OSError on mkdir."""
    import api.app.routes.resync as rm
    from pathlib import Path

    def _boom(self, *a, **kw):
        raise OSError("permission denied")

    real = Path.mkdir
    monkeypatch.setattr(Path, "mkdir", _boom)
    try:
        monkeypatch.setattr(rm, "TRIGGER_DIR", tmp_path / "xx")
        rm._ensure_trigger_dir()
    finally:
        monkeypatch.setattr(Path, "mkdir", real)
