"""main.py coverage — _split_sql utility, whoami endpoint."""

import pytest

# _split_sql unit tests


def test_split_sql_simple():
    """Split simple SQL statements."""
    from api.app.main import _split_sql

    sql = "CREATE TABLE foo (id INT);\nCREATE TABLE bar (id INT);"
    stmts = _split_sql(sql)
    assert len(stmts) == 2
    assert "foo" in stmts[0]
    assert "bar" in stmts[1]


def test_split_sql_with_comments():
    """Comments are stripped."""
    from api.app.main import _split_sql

    sql = "-- this is a comment\nCREATE TABLE foo (id INT);"
    stmts = _split_sql(sql)
    assert len(stmts) == 1
    assert "--" not in stmts[0]


def test_split_sql_dollar_blocks():
    """$$ blocks (functions/triggers) are kept intact."""
    from api.app.main import _split_sql

    sql = (
        "CREATE FUNCTION test() RETURNS void AS $$\n"
        "BEGIN\n"
        "  -- inner comment preserved\n"
        "  RAISE NOTICE 'test';\n"
        "END;\n"
        "$$ LANGUAGE plpgsql;"
    )
    stmts = _split_sql(sql)
    assert len(stmts) == 1
    assert "$$" in stmts[0]
    assert "inner comment" in stmts[0]


def test_split_sql_empty():
    """Empty SQL returns empty list."""
    from api.app.main import _split_sql

    assert _split_sql("") == []
    assert _split_sql("-- only comments") == []


def test_split_sql_trailing_content():
    """SQL without trailing semicolon is still captured."""
    from api.app.main import _split_sql

    sql = "SELECT 1;\nSELECT 2"
    stmts = _split_sql(sql)
    assert len(stmts) == 2


# whoami endpoint


@pytest.mark.anyio
async def test_whoami(client, auth):
    """whoami returns user identity."""
    r = await client.get("/api/v1/whoami", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "user" in data
    assert "role" in data
    assert "name" in data


@pytest.mark.anyio
async def test_whoami_no_auth(client):
    """whoami without auth returns 401."""
    r = await client.get("/api/v1/whoami")
    assert r.status_code == 401
