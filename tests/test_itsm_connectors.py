"""ITSM connectors — priority mapping + inbound status parsing."""

import httpx
import pytest

from api.app.connectors.glpi import GLPIConnector
from api.app.connectors.jira import JiraConnector
from api.app.connectors.zammad import ZammadConnector


def test_glpi_parse_inbound_status():
    c = GLPIConnector("https://x", {"app_token": "a", "user_token": "u"})
    tid, status = c.parse_inbound_status({"items_id": 42, "status": 5})
    assert tid == "42"
    assert status == "5"


def test_glpi_parse_inbound_without_id():
    c = GLPIConnector("https://x", {"app_token": "a", "user_token": "u"})
    tid, status = c.parse_inbound_status({"foo": "bar"})
    assert tid is None


def test_zammad_parse_inbound_nested():
    c = ZammadConnector("https://x", {"token": "z"})
    tid, status = c.parse_inbound_status({"ticket": {"id": 10, "state": "closed"}})
    assert tid == "10"
    assert status == "closed"


def test_zammad_parse_inbound_flat():
    c = ZammadConnector("https://x", {"token": "z"})
    tid, status = c.parse_inbound_status({"id": 7, "state": "open"})
    assert tid == "7"
    assert status == "open"


def test_jira_parse_inbound_status():
    c = JiraConnector(
        "https://x",
        {"email": "a@b.c", "api_token": "t"},
        project_key="INC",
    )
    tid, status = c.parse_inbound_status(
        {"issue": {"key": "INC-5", "fields": {"status": {"name": "Done"}}}}
    )
    assert tid == "INC-5"
    assert status == "Done"


def test_jira_platform_identifier():
    c = JiraConnector("https://x", {}, project_key="INC")
    assert c.platform == "jira"


def test_glpi_platform_identifier():
    c = GLPIConnector("https://x", {})
    assert c.platform == "glpi"


def test_zammad_platform_identifier():
    c = ZammadConnector("https://x", {})
    assert c.platform == "zammad"


def test_get_itsm_factory():
    from api.app.connectors import get_itsm

    c = get_itsm("glpi", "https://x", {"app_token": "a", "user_token": "u"})
    assert isinstance(c, GLPIConnector)
    c = get_itsm("zammad", "https://x", {"token": "z"})
    assert isinstance(c, ZammadConnector)
    c = get_itsm("jira", "https://x", {"email": "a", "api_token": "t"}, "PRJ")
    assert isinstance(c, JiraConnector)
    assert c.project_key == "PRJ"


def test_get_itsm_unknown_platform():
    from api.app.connectors import get_itsm

    with pytest.raises(ValueError):
        get_itsm("servicenow", "https://x", {})


# HTTP-path coverage via httpx MockTransport


def _mock_client_factory(route):
    """Return a patch target that yields an AsyncClient with a MockTransport."""
    transport = httpx.MockTransport(route)
    real_ac = httpx.AsyncClient

    def _factory(*args, **kwargs):
        kwargs["transport"] = transport
        return real_ac(*args, **kwargs)

    return _factory


@pytest.mark.anyio
async def test_glpi_test_connection_and_create_ticket(monkeypatch):
    calls = []

    def route(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        if request.url.path.endswith("/initSession"):
            return httpx.Response(200, json={"session_token": "x"})
        return httpx.Response(201, json={"id": 777})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(route))

    c = GLPIConnector("https://glpi", {"app_token": "a", "user_token": "u"})
    r = await c.test_connection()
    assert r["status"] == "ok"

    tid, url = await c.create_ticket("t", "body", "P1", labels=["x"])
    assert tid == "777"
    assert "ticket.form.php?id=777" in url


@pytest.mark.anyio
async def test_zammad_test_connection_and_create_ticket(monkeypatch):
    def route(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/users/me"):
            return httpx.Response(200, json={"login": "bot"})
        return httpx.Response(201, json={"id": 42})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(route))

    c = ZammadConnector("https://z", {"token": "t"})
    r = await c.test_connection()
    assert r["status"] == "ok"
    assert r["info"] == "bot"

    tid, url = await c.create_ticket("t", "body", "P2")
    assert tid == "42"
    assert "ticket/zoom/42" in url


@pytest.mark.anyio
async def test_jira_test_connection_and_create_ticket(monkeypatch):
    def route(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/myself"):
            return httpx.Response(200, json={"emailAddress": "bot@j"})
        return httpx.Response(201, json={"key": "INC-100"})

    monkeypatch.setattr(httpx, "AsyncClient", _mock_client_factory(route))

    c = JiraConnector("https://j", {"email": "a@b.c", "api_token": "t"}, "INC")
    r = await c.test_connection()
    assert r["status"] == "ok"

    tid, url = await c.create_ticket("t", "body", "P3")
    assert tid == "INC-100"
    assert "/browse/INC-100" in url


@pytest.mark.anyio
async def test_jira_create_ticket_without_project_key_raises(monkeypatch):
    c = JiraConnector("https://j", {"email": "a@b.c", "api_token": "t"})
    with pytest.raises(ValueError):
        await c.create_ticket("t", "body", "P1")
