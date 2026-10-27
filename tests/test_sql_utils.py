"""SQL utility functions coverage."""

from api.app.utils.sql import order_clause, where_clause


def test_where_clause_empty():
    """Empty clauses returns empty string."""
    assert where_clause([]) == ""


def test_where_clause_single():
    """Single clause builds WHERE."""
    assert where_clause(["col = :val"]) == "WHERE col = :val"


def test_where_clause_multiple():
    """Multiple clauses joined with AND."""
    result = where_clause(["a = :a", "b = :b"])
    assert result == "WHERE a = :a AND b = :b"


def test_order_clause_default():
    """No sort_by returns default order."""
    result = order_clause(None, {"name": "n.name"}, default="n.id")
    assert result == "ORDER BY n.id"


def test_order_clause_valid():
    """Valid sort key builds ORDER BY."""
    result = order_clause("name", {"name": "n.name"}, "asc")
    assert result == "ORDER BY n.name ASC"


def test_order_clause_desc():
    """DESC direction works."""
    result = order_clause("name", {"name": "n.name"}, "desc")
    assert result == "ORDER BY n.name DESC"


def test_order_clause_unknown_key():
    """Unknown sort key falls back to default."""
    result = order_clause("unknown", {"name": "n.name"}, default="n.id")
    assert result == "ORDER BY n.id"


def test_order_clause_no_default():
    """Unknown key with no default returns empty."""
    result = order_clause("unknown", {"name": "n.name"})
    assert result == ""


def test_order_clause_invalid_direction():
    """Invalid direction defaults to ASC."""
    result = order_clause("name", {"name": "n.name"}, "INVALID")
    assert result == "ORDER BY n.name ASC"
