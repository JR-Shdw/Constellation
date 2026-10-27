"""Managers — test connection, list images, pull image (mocked Portainer)."""

import uuid
from unittest.mock import AsyncMock, patch

import pytest


@pytest.fixture
async def manager_id(client, auth):
    """Create a manager and return its ID."""
    r = await client.post(
        "/api/v1/managers",
        json={
            "name": f"ptr-test-{uuid.uuid4().hex[:8]}",
            "manager_type": "portainer",
            "url": "https://portainer.test:9443",
            "token": "ptr_mock_token",
            "endpoint_id": 1,
            "tls_skip_verify": True,
        },
        headers=auth,
    )
    return r.json()["id"]


@pytest.mark.anyio
async def test_test_connection_success(client, auth, manager_id):
    """Test connection success updates status to connected."""
    with patch(
        "api.app.routes.managers.PortainerClient.test_connection",
        new_callable=AsyncMock,
        return_value={"Version": "2.20.0", "InstanceID": "abc123"},
    ):
        r = await client.post(f"/api/v1/managers/{manager_id}/test", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "Version" in data["detail"]


@pytest.mark.anyio
async def test_test_connection_failure(client, auth, manager_id):
    """Test connection failure updates status to error."""
    with patch(
        "api.app.routes.managers.PortainerClient.test_connection",
        new_callable=AsyncMock,
        side_effect=ConnectionError("Connection refused"),
    ):
        r = await client.post(f"/api/v1/managers/{manager_id}/test", headers=auth)
        assert r.status_code == 502
        assert "Connection failed" in r.json()["detail"]


@pytest.mark.anyio
async def test_list_images(client, auth, manager_id):
    """List images from Portainer endpoint."""
    mock_images = [
        {
            "Id": "sha256:abc123456789abcdef0123456789",
            "RepoTags": ["nginx:1.25", "nginx:latest"],
            "Size": 187654321,
            "Created": 1700000000,
        },
        {
            "Id": "sha256:def456789012345678901234567",
            "RepoTags": ["postgres:17"],
            "Size": 412345678,
            "Created": 1700100000,
        },
    ]
    with patch(
        "api.app.routes.managers.PortainerClient.list_images",
        new_callable=AsyncMock,
        return_value=mock_images,
    ):
        r = await client.get(f"/api/v1/managers/{manager_id}/images", headers=auth)
        assert r.status_code == 200
        data = r.json()
        assert len(data["items"]) == 2
        assert data["items"][0]["tags"] == ["nginx:1.25", "nginx:latest"]
        assert data["items"][0]["id"] == "sha256:abc123456789"


@pytest.mark.anyio
async def test_list_images_api_error(client, auth, manager_id):
    """List images handles Portainer API error."""
    with patch(
        "api.app.routes.managers.PortainerClient.list_images",
        new_callable=AsyncMock,
        side_effect=Exception("API timeout"),
    ):
        r = await client.get(f"/api/v1/managers/{manager_id}/images", headers=auth)
        assert r.status_code == 502


@pytest.mark.anyio
async def test_pull_image_success(client, auth, manager_id):
    """Pull image from Portainer endpoint."""
    with patch(
        "api.app.routes.managers.PortainerClient.pull_image",
        new_callable=AsyncMock,
        return_value={"status": "ok", "image": "nginx:latest"},
    ):
        r = await client.post(
            f"/api/v1/managers/{manager_id}/pull",
            json={"image": "nginx", "tag": "latest"},
            headers=auth,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "ok"


@pytest.mark.anyio
async def test_pull_image_failure(client, auth, manager_id):
    """Pull image failure returns 502."""
    with patch(
        "api.app.routes.managers.PortainerClient.pull_image",
        new_callable=AsyncMock,
        side_effect=Exception("Pull failed: unauthorized"),
    ):
        r = await client.post(
            f"/api/v1/managers/{manager_id}/pull",
            json={"image": "private/img", "tag": "v1"},
            headers=auth,
        )
        assert r.status_code == 502


@pytest.mark.anyio
async def test_pull_image_signature_refused(client, auth, manager_id):
    """Trusted-namespace image with bad signature returns 403, not 502.

    The consumer gate (api/app/utils/image_verify.py) raises
    SignatureError for images in trust-mapped namespaces whose cosign
    signature doesn't verify. The route must surface that as 403 so
    operators see the cause is policy, not a flaky portainer.
    """
    from api.app.utils.image_verify import SignatureError

    with patch(
        "api.app.routes.managers.PortainerClient.pull_image",
        new_callable=AsyncMock,
        side_effect=SignatureError(
            "signature verification failed for "
            "gitea.example.com/shdw/rhorizon-api:latest: bad sig"
        ),
    ):
        r = await client.post(
            f"/api/v1/managers/{manager_id}/pull",
            json={"image": "gitea.example.com/shdw/rhorizon-api", "tag": "latest"},
            headers=auth,
        )
        assert r.status_code == 403
        assert "Signature verification failed" in r.json()["detail"]


# PortainerClient.pull_image — Docker streams pull errors in-band with HTTP 200


def test_docker_stream_error_detects_inband_error():
    from api.app.utils.portainer import _docker_stream_error

    # Newline-delimited progress then an error object (real Docker shape).
    stream = (
        '{"status":"Pulling from library/nginx"}\n'
        '{"status":"Pulling fs layer"}\n'
        '{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}\n'
    )
    assert _docker_stream_error(stream) == "manifest unknown"
    # Concatenated objects without newlines must also be walked.
    assert _docker_stream_error('{"status":"x"}{"error":"boom"}') == "boom"
    # Clean pull → no error.
    assert (
        _docker_stream_error('{"status":"Pull complete"}\n{"status":"Downloaded"}')
        is None
    )


@pytest.mark.anyio
async def test_pull_image_raises_on_inband_error(monkeypatch):
    """A 200 response whose stream carries an error must raise, not return ok."""
    from api.app.utils import portainer

    class _Resp:
        status_code = 200
        text = '{"status":"Pulling"}\n{"error":"unauthorized: access denied"}\n'

        def raise_for_status(self):
            return None

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return _Resp()

    monkeypatch.setattr(portainer.httpx, "AsyncClient", lambda *a, **k: _Client())

    client = portainer.PortainerClient("https://ptr.test", "tok")
    # 'nginx' is an untrusted namespace → verify_image passes through.
    with pytest.raises(RuntimeError, match="unauthorized"):
        await client.pull_image("nginx", "latest")


@pytest.mark.anyio
async def test_pull_image_ok_on_clean_stream(monkeypatch):
    from api.app.utils import portainer

    class _Resp:
        status_code = 200
        text = '{"status":"Pulling"}\n{"status":"Status: Downloaded nginx:latest"}\n'

        def raise_for_status(self):
            return None

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, *a, **k):
            return _Resp()

    monkeypatch.setattr(portainer.httpx, "AsyncClient", lambda *a, **k: _Client())

    client = portainer.PortainerClient("https://ptr.test", "tok")
    result = await client.pull_image("nginx", "latest")
    assert result == {"status": "ok", "image": "nginx:latest"}


@pytest.mark.anyio
async def test_test_connection_not_found(client, auth):
    """Test connection on nonexistent manager."""
    r = await client.post(f"/api/v1/managers/{uuid.uuid4()}/test", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_list_images_not_found(client, auth):
    """List images on nonexistent manager."""
    r = await client.get(f"/api/v1/managers/{uuid.uuid4()}/images", headers=auth)
    assert r.status_code == 404


@pytest.mark.anyio
async def test_pull_image_not_found(client, auth):
    """Pull image on nonexistent manager."""
    r = await client.post(
        f"/api/v1/managers/{uuid.uuid4()}/pull",
        json={"image": "nginx", "tag": "latest"},
        headers=auth,
    )
    assert r.status_code == 404
