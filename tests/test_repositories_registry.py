"""Repositories — registry detection, CRUD, check coverage."""

import uuid

import pytest

# Registry detection


def test_detect_registry_dockerhub():
    """Plain image name detected as DockerHub."""
    from api.app.routes.repositories import _detect_registry

    reg, name = _detect_registry("nginx", "")
    assert reg == "dockerhub"


def test_detect_registry_ghcr():
    """ghcr.io image detected as GHCR."""
    from api.app.routes.repositories import _detect_registry

    reg, name = _detect_registry("ghcr.io/owner/repo", "")
    assert reg == "ghcr"
    assert "ghcr.io" not in name


def test_detect_registry_oci():
    """Private registry image detected as OCI."""
    from api.app.routes.repositories import _detect_registry

    reg, name = _detect_registry("registry.example.com/myapp", "")
    assert reg == "oci"


def test_detect_registry_existing():
    """Explicitly set registry is preserved."""
    from api.app.routes.repositories import _detect_registry

    reg, name = _detect_registry("myimage", "ghcr")
    assert reg == "ghcr"


def test_detect_registry_port():
    """Image with port in first part detected as OCI."""
    from api.app.routes.repositories import _detect_registry

    reg, name = _detect_registry("registry.local:5000/app", "")
    assert reg == "oci"


# CRUD


@pytest.mark.anyio
async def test_add_repository(client, auth):
    """Add a Docker repository."""
    name = f"test/repo-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": name,
            "current_tag": "1.0.0",
            "registry": "dockerhub",
        },
        headers=auth,
    )
    assert r.status_code in (200, 201)
    assert "id" in r.json()


@pytest.mark.anyio
async def test_list_repositories(client, auth):
    """List Docker repositories."""
    r = await client.get("/api/v1/repositories", headers=auth)
    assert r.status_code == 200
    assert "items" in r.json()


@pytest.mark.anyio
async def test_check_repo_not_found(client, auth):
    """Check non-existent repo returns error in response."""
    fake_id = "00000000-0000-0000-0000-000000000001"
    r = await client.post(f"/api/v1/repositories/{fake_id}/check", headers=auth)
    assert r.status_code == 200
    assert r.json().get("error") == "not found"


@pytest.mark.anyio
async def test_delete_repo(client, auth):
    """Delete a repository."""
    name = f"del/repo-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": name,
            "current_tag": "latest",
            "registry": "dockerhub",
        },
        headers=auth,
    )
    repo_id = r.json()["id"]
    r = await client.delete(f"/api/v1/repositories/{repo_id}", headers=auth)
    assert r.status_code == 200


@pytest.mark.anyio
async def test_patch_repo(client, auth):
    """Patch repository fields."""
    name = f"patch/repo-{uuid.uuid4().hex[:8]}"
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": name,
            "current_tag": "1.0",
            "registry": "dockerhub",
        },
        headers=auth,
    )
    repo_id = r.json()["id"]
    r = await client.patch(
        f"/api/v1/repositories/{repo_id}",
        json={"current_tag": "2.0"},
        headers=auth,
    )
    assert r.status_code == 200


@pytest.mark.anyio
async def test_check_all_repos(client, auth):
    """Check all repos (may return empty)."""
    r = await client.post("/api/v1/repositories/check-all", headers=auth)
    assert r.status_code == 200


# OCI resolve_latest — anonymous + bearer auth + failure paths


class _FakeResp:
    def __init__(self, status_code=200, data=None, headers=None):
        self.status_code = status_code
        self._data = data or {}
        self.headers = headers or {}

    def json(self):
        return self._data


class _FakeClient:
    """Async context manager mimicking httpx.AsyncClient — call sequence driven."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, headers=None):
        self.calls.append((url, headers or {}))
        return self._responses.pop(0)


@pytest.mark.anyio
async def test_resolve_latest_oci_anonymous_success(monkeypatch):
    """OCI registry returns 200 on first call → latest tag picked."""
    from api.app.routes import repositories

    responses = [_FakeResp(200, {"tags": ["v1.0.0", "v1.2.0", "v1.1.0"]})]
    client = _FakeClient(responses)
    monkeypatch.setattr(repositories.httpx, "AsyncClient", lambda *a, **k: client)

    latest = await repositories.resolve_latest("registry.example.com/team/app", "")
    assert latest == "v1.2.0"


@pytest.mark.anyio
async def test_resolve_latest_oci_bearer_auth(monkeypatch):
    """OCI 401 → follow www-authenticate → token → retry returns tags."""
    from api.app.routes import repositories

    www = (
        'Bearer realm="https://auth.example.com/token",scope="repository:team/app:pull"'
    )
    responses = [
        _FakeResp(401, headers={"www-authenticate": www}),
        _FakeResp(200, {"token": "xyz"}),  # token endpoint
        _FakeResp(200, {"tags": ["1.0", "2.0"]}),  # retry with bearer
    ]
    client = _FakeClient(responses)
    monkeypatch.setattr(repositories.httpx, "AsyncClient", lambda *a, **k: client)

    latest = await repositories.resolve_latest("registry.example.com/team/app", "")
    assert latest == "2.0"
    # Third call must carry the bearer header
    third_url, third_headers = client.calls[2]
    assert third_headers["Authorization"] == "Bearer xyz"


@pytest.mark.anyio
async def test_resolve_latest_oci_non_200_returns_none(monkeypatch):
    """Registry replies 404 → resolve_latest returns None gracefully."""
    from api.app.routes import repositories

    client = _FakeClient([_FakeResp(404)])
    monkeypatch.setattr(repositories.httpx, "AsyncClient", lambda *a, **k: client)

    latest = await repositories.resolve_latest("registry.example.com/missing/app", "")
    assert latest is None


@pytest.mark.anyio
async def test_resolve_latest_oci_exception_swallowed(monkeypatch):
    """httpx.ConnectError → logged + returns None, does not raise."""
    from api.app.routes import repositories

    class _Boom:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **k):
            raise RuntimeError("DNS error")

    monkeypatch.setattr(repositories.httpx, "AsyncClient", lambda *a, **k: _Boom())

    latest = await repositories.resolve_latest("registry.example.com/team/app", "")
    assert latest is None


@pytest.mark.anyio
async def test_resolve_latest_oci_no_repo_path_returns_none():
    """Image is just a hostname (no path after /) → no query, None."""
    from api.app.routes.repositories import resolve_latest

    # "registry.example.com:5000" → first_part has `:`, so OCI branch,
    # but split('/', 1) yields a single element → repo_path empty → None.
    assert await resolve_latest("registry.example.com:5000", "") is None


# Report path — empty image_name must be skipped


@pytest.mark.anyio
async def test_report_skips_empty_image_name(client, auth, collect_auth):
    """images entry without image_name → `continue` before INSERT."""
    r = await client.post(
        "/api/v1/repositories/report",
        json={
            "hostname": "ghost",
            "images": [
                {"image_name": ""},  # skipped
                {"image_name": "nginx", "current_tag": "1.25"},
            ],
        },
        headers=collect_auth,
    )
    assert r.status_code == 200
    # Only the non-empty image is counted.
    assert r.json()["upserted"] == 1


# check_repository_version — automation eval failure branch


@pytest.mark.anyio
async def test_check_automation_failure_swallowed(client, auth, monkeypatch):
    """run_evaluation exception in /check is caught + logged, not re-raised."""
    from api.app.routes import repositories

    # Seed a repo manually so /check finds a row.
    r = await client.post(
        "/api/v1/repositories",
        json={
            "image_name": "nginx",
            "current_tag": "1.20",
            "registry": "dockerhub",
        },
        headers=auth,
    )
    repo_id = r.json()["id"]

    async def _fake_resolve(name, registry, current=None):
        return "1.30"  # newer → update_available path

    async def _boom(*a, **k):
        raise RuntimeError("automation boom")

    monkeypatch.setattr(repositories, "resolve_latest", _fake_resolve)
    monkeypatch.setattr(repositories, "run_evaluation", _boom)

    r = await client.post(f"/api/v1/repositories/{repo_id}/check", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert data["update_available"] is True


@pytest.mark.anyio
async def test_check_all_automation_failure_swallowed(client, auth, monkeypatch):
    """/check-all must keep iterating when run_evaluation raises."""
    from api.app.routes import repositories

    for tag in ("1.0", "2.0"):
        await client.post(
            "/api/v1/repositories",
            json={
                "image_name": f"nginx-{tag}",
                "current_tag": tag,
                "registry": "dockerhub",
            },
            headers=auth,
        )

    async def _fake_resolve(name, registry, current=None):
        return "99.0"

    async def _boom(*a, **k):
        raise RuntimeError("eval boom")

    monkeypatch.setattr(repositories, "resolve_latest", _fake_resolve)
    monkeypatch.setattr(repositories, "run_evaluation", _boom)

    r = await client.post("/api/v1/repositories/check-all", headers=auth)
    assert r.status_code == 200
    assert r.json()["checked"] >= 2


# _pick_latest — variant-aware latest resolution


def test_pick_latest_respects_current_variant():
    """A '-alpine' image gets the highest '-alpine' tag, not a higher debian one."""
    from api.app.routes.repositories import _pick_latest

    tags = ["3.18-alpine", "3.19-alpine", "3.20", "3.20.1"]
    # current is alpine -> 3.20/3.20.1 (debian) excluded -> highest alpine wins
    assert _pick_latest(tags, "3.18-alpine") == "3.19-alpine"


def test_pick_latest_no_current_is_global_highest():
    """No current_tag → legacy behaviour: global highest version."""
    from api.app.routes.repositories import _pick_latest

    assert _pick_latest(["1.0.0", "1.2.0", "1.1.0"], None) == "1.2.0"


def test_pick_latest_non_version_current_is_global_highest():
    """current='latest' isn't a version tag → fall back to global highest."""
    from api.app.routes.repositories import _pick_latest

    assert _pick_latest(["2.1", "2.3", "2.2"], "latest") == "2.3"


def test_pick_latest_empty_returns_none():
    from api.app.routes.repositories import _pick_latest

    assert _pick_latest([], "1.0") is None
    assert _pick_latest(["latest", "main"], "1.0") is None  # no version tags


# tag_sortkey — trailing zeros must not invent an update (1.2 == 1.2.0)


def test_tag_sortkey_trailing_zeros_equal():
    from api.app.connectors.registry import tag_sortkey

    assert tag_sortkey("1.2") == tag_sortkey("1.2.0")
    assert tag_sortkey("1.2") == tag_sortkey("1.2.0.0")
    assert tag_sortkey("1.0") == tag_sortkey("1")
    # Real ordering preserved.
    assert tag_sortkey("1.2.1") > tag_sortkey("1.2")
    assert tag_sortkey("1.10") > tag_sortkey("1.9")


def test_evaluate_update_1_2_vs_1_2_0_not_an_update():
    """Regression: '1.2' deployed, registry exposes '1.2.0' → no bogus update."""
    from api.app.routes.repositories import _evaluate_update

    assert _evaluate_update("1.2", "1.2.0") == ("1.2.0", False)


# _filter_tags — pre-release fragments matched as tokens, not bare substrings


def test_filter_tags_keeps_stable_with_fragment_substring():
    from api.app.connectors.registry import _filter_tags

    # 'rc' lives inside 'source' / '1.0' is a real version → must be kept.
    assert _filter_tags(["1.0-source"]) == ["1.0-source"]


def test_filter_tags_drops_real_prereleases():
    from api.app.connectors.registry import _filter_tags

    dropped = ["1.0-rc1", "2.0.0-beta", "3.11.0-dev", "1.0rc1", "1.2.3-alpha.2"]
    assert _filter_tags(dropped) == []


def test_filter_tags_keeps_variant_suffixes():
    from api.app.connectors.registry import _filter_tags

    kept = ["3.18-alpine", "1.27.3-bookworm", "17.2"]
    assert _filter_tags(kept) == kept


# _evaluate_update — comparable-only latest, no misleading 'latest -> x' mismatch


def test_evaluate_update_latest_current_is_no_mismatch():
    """'latest'-pinned image: no bogus version update, latest_tag stays None."""
    from api.app.routes.repositories import _evaluate_update

    assert _evaluate_update("latest", "3.5") == (None, False)
    assert _evaluate_update("main", "v2.1.0") == (None, False)


def test_evaluate_update_same_variant_update():
    from api.app.routes.repositories import _evaluate_update

    assert _evaluate_update("3.18-alpine", "3.19-alpine") == ("3.19-alpine", True)


def test_evaluate_update_different_variant_not_comparable():
    from api.app.routes.repositories import _evaluate_update

    assert _evaluate_update("3.18-alpine", "3.20") == (None, False)


def test_evaluate_update_already_on_latest():
    from api.app.routes.repositories import _evaluate_update

    assert _evaluate_update("1.2.0", "1.2.0") == ("1.2.0", False)


# _detect_registry — explicit DockerHub host must use the Hub API, not OCI


def test_detect_registry_explicit_dockerhub_host():
    from api.app.routes.repositories import _detect_registry

    assert _detect_registry("docker.io/library/nginx", "dockerhub") == (
        "dockerhub",
        "library/nginx",
    )
    assert _detect_registry("docker.io/grafana/grafana", "dockerhub") == (
        "dockerhub",
        "grafana/grafana",
    )


def test_detect_registry_ghcr_oci_and_plain():
    from api.app.routes.repositories import _detect_registry

    assert _detect_registry("ghcr.io/owner/repo", "dockerhub") == ("ghcr", "owner/repo")
    assert _detect_registry("git.example.com:5050/g/r", "dockerhub") == (
        "oci",
        "git.example.com:5050/g/r",
    )
    assert _detect_registry("nginx", "dockerhub") == ("dockerhub", "nginx")


# Digest comparison — latest-pinned image update detection


def test_norm_digest():
    from api.app.routes.repositories import _norm_digest

    assert _norm_digest("traefik@sha256:abc") == "sha256:abc"
    assert _norm_digest("sha256:abc") == "sha256:abc"
    assert _norm_digest("  sha256:abc  ") == "sha256:abc"
    assert _norm_digest("") is None
    assert _norm_digest(None) is None


def test_evaluate_digest():
    from api.app.routes.repositories import _evaluate_digest

    # Different digests → update available
    assert _evaluate_digest("sha256:old", "sha256:new") is True
    # Same digest (one as RepoDigest, one bare) → normalised equal → no update
    assert _evaluate_digest("img@sha256:same", "sha256:same") is False
    # Missing either side → no signal, no update
    assert _evaluate_digest(None, "sha256:new") is False
    assert _evaluate_digest("sha256:old", None) is False
    assert _evaluate_digest("", "sha256:new") is False


def test_registry_host_repo():
    from api.app.routes.repositories import _registry_host_repo

    assert _registry_host_repo("dockerhub", "nginx") == (
        "registry-1.docker.io",
        "library/nginx",
    )
    assert _registry_host_repo("dockerhub", "grafana/grafana") == (
        "registry-1.docker.io",
        "grafana/grafana",
    )
    assert _registry_host_repo("ghcr", "owner/repo") == ("ghcr.io", "owner/repo")
    assert _registry_host_repo("ghcr", "owner") is None  # no repo path
    assert _registry_host_repo("oci", "git.example.com/g/r") == (
        "git.example.com",
        "g/r",
    )
    assert _registry_host_repo("oci", "git.example.com") is None  # host only


@pytest.mark.anyio
async def test_resolve_remote_digest_anonymous(monkeypatch):
    """200 on first call → Docker-Content-Digest header returned, normalised."""
    from api.app.routes import repositories

    client = _FakeClient(
        [_FakeResp(200, headers={"docker-content-digest": "sha256:deadbeef"})]
    )
    monkeypatch.setattr(repositories.httpx, "AsyncClient", lambda *a, **k: client)

    digest = await repositories.resolve_remote_digest(
        "registry.example.com/team/app", "", "latest"
    )
    assert digest == "sha256:deadbeef"
    # Manifest endpoint queried with the index/list Accept header.
    url, headers = client.calls[0]
    assert url == "https://registry.example.com/v2/team/app/manifests/latest"
    assert "manifest.list" in headers["Accept"]


@pytest.mark.anyio
async def test_resolve_remote_digest_bearer_with_service(monkeypatch):
    """401 → token dance (service= required by DockerHub) → retry returns digest."""
    from api.app.routes import repositories

    www = (
        'Bearer realm="https://auth.docker.io/token",'
        'service="registry.docker.io",scope="repository:library/nginx:pull"'
    )
    client = _FakeClient(
        [
            _FakeResp(401, headers={"www-authenticate": www}),
            _FakeResp(200, {"token": "tok123"}),
            _FakeResp(200, headers={"docker-content-digest": "sha256:cafe"}),
        ]
    )
    monkeypatch.setattr(repositories.httpx, "AsyncClient", lambda *a, **k: client)

    digest = await repositories.resolve_remote_digest("nginx", "dockerhub", "latest")
    assert digest == "sha256:cafe"
    # Token request must carry service= (DockerHub rejects tokens without it).
    token_url, _ = client.calls[1]
    assert "service=registry.docker.io" in token_url
    # Retry carries the bearer token.
    _, retry_headers = client.calls[2]
    assert retry_headers["Authorization"] == "Bearer tok123"


@pytest.mark.anyio
async def test_resolve_remote_digest_non_200_none(monkeypatch):
    from api.app.routes import repositories

    client = _FakeClient([_FakeResp(404)])
    monkeypatch.setattr(repositories.httpx, "AsyncClient", lambda *a, **k: client)
    assert (
        await repositories.resolve_remote_digest("nginx", "dockerhub", "latest") is None
    )


@pytest.mark.anyio
async def test_resolve_remote_digest_no_repo_path_none(monkeypatch):
    """Image without a repo path → no query attempted, None."""
    from api.app.routes import repositories

    # Must not even build a client — assert by making AsyncClient explode.
    def _boom(*a, **k):
        raise AssertionError("should not query the registry")

    monkeypatch.setattr(repositories.httpx, "AsyncClient", _boom)
    assert (
        await repositories.resolve_remote_digest("ghcr.io/owner", "", "latest") is None
    )


@pytest.mark.anyio
async def test_check_digest_update_for_latest_pinned(
    client, auth, collect_auth, monkeypatch
):
    """latest-pinned tag: deployed digest != remote digest → update_available."""
    from api.app.routes import repositories

    image = f"acme/web-{uuid.uuid4().hex[:8]}"
    # Seed with a current_digest via the collector /report path.
    await client.post(
        "/api/v1/repositories/report",
        json={
            "hostname": "ghost",
            "images": [
                {
                    "image_name": image,
                    "current_tag": "latest",
                    "current_digest": "sha256:OLD",
                    "registry": "dockerhub",
                }
            ],
        },
        headers=collect_auth,
    )
    listing = (await client.get("/api/v1/repositories", headers=auth)).json()
    repo_id = next(r["id"] for r in listing["items"] if r["image_name"] == image)

    async def _no_tag(*a, **k):
        return None  # no comparable version tag

    async def _remote(*a, **k):
        return "sha256:NEW"

    monkeypatch.setattr(repositories, "resolve_latest", _no_tag)
    monkeypatch.setattr(repositories, "resolve_remote_digest", _remote)

    r = await client.post(f"/api/v1/repositories/{repo_id}/check", headers=auth)
    data = r.json()
    assert data["update_available"] is True
    assert data["latest_digest"] == "sha256:NEW"


@pytest.mark.anyio
async def test_check_all_dedups_registry_lookups(
    client, auth, collect_auth, monkeypatch
):
    """check-all resolves each unique image once, not once per host row.

    At scale the same image:tag lives on many hosts (N repository rows); the
    registry must be hit once per unique (image, registry, tag), not N times.
    """
    from api.app.routes import repositories

    image = f"acme/dedup-{uuid.uuid4().hex[:8]}"
    for i in range(3):
        await client.post(
            "/api/v1/repositories/report",
            json={
                "hostname": f"ddp-{i}-{uuid.uuid4().hex[:6]}",
                "images": [
                    {
                        "image_name": image,
                        "current_tag": "latest",
                        "current_digest": "sha256:OLD",
                        "registry": "dockerhub",
                    }
                ],
            },
            headers=collect_auth,
        )

    latest_calls = {"n": 0}
    digest_calls = {"n": 0}

    async def _fake_latest(name, registry, current=None):
        latest_calls["n"] += 1
        return None  # latest-pinned → no comparable tag update

    async def _fake_digest(name, registry, tag):
        digest_calls["n"] += 1
        return "sha256:NEW"

    monkeypatch.setattr(repositories, "resolve_latest", _fake_latest)
    monkeypatch.setattr(repositories, "resolve_remote_digest", _fake_digest)

    r = await client.post("/api/v1/repositories/check-all", headers=auth)
    assert r.status_code == 200
    assert r.json()["checked"] >= 3
    # One unique image → exactly one registry lookup each, despite 3 rows.
    assert latest_calls["n"] == 1
    assert digest_calls["n"] == 1


@pytest.mark.anyio
async def test_check_digest_up_to_date(client, auth, collect_auth, monkeypatch):
    """latest-pinned tag: deployed digest == remote digest → no update."""
    from api.app.routes import repositories

    image = f"acme/api-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/repositories/report",
        json={
            "hostname": "ghost",
            "images": [
                {
                    "image_name": image,
                    "current_tag": "latest",
                    "current_digest": "img@sha256:SAME",
                    "registry": "dockerhub",
                }
            ],
        },
        headers=collect_auth,
    )
    listing = (await client.get("/api/v1/repositories", headers=auth)).json()
    repo_id = next(r["id"] for r in listing["items"] if r["image_name"] == image)

    async def _no_tag(*a, **k):
        return None

    async def _remote(*a, **k):
        return "sha256:SAME"  # bare form, equal after normalisation

    monkeypatch.setattr(repositories, "resolve_latest", _no_tag)
    monkeypatch.setattr(repositories, "resolve_remote_digest", _remote)

    r = await client.post(f"/api/v1/repositories/{repo_id}/check", headers=auth)
    assert r.json()["update_available"] is False


@pytest.mark.anyio
async def test_check_version_tag_skips_digest(client, auth, collect_auth, monkeypatch):
    """A version tag uses tag comparison only — digest path must not run."""
    from api.app.routes import repositories

    image = f"acme/svc-{uuid.uuid4().hex[:8]}"
    await client.post(
        "/api/v1/repositories/report",
        json={
            "hostname": "ghost",
            "images": [
                {
                    "image_name": image,
                    "current_tag": "1.2.0",
                    "current_digest": "sha256:OLD",
                    "registry": "dockerhub",
                }
            ],
        },
        headers=collect_auth,
    )
    listing = (await client.get("/api/v1/repositories", headers=auth)).json()
    repo_id = next(r["id"] for r in listing["items"] if r["image_name"] == image)

    async def _no_tag(*a, **k):
        return None  # already latest version-wise

    async def _remote(*a, **k):
        raise AssertionError("digest path must not run for a version tag")

    monkeypatch.setattr(repositories, "resolve_latest", _no_tag)
    monkeypatch.setattr(repositories, "resolve_remote_digest", _remote)

    r = await client.post(f"/api/v1/repositories/{repo_id}/check", headers=auth)
    assert r.json()["update_available"] is False
    assert r.json()["latest_digest"] is None
