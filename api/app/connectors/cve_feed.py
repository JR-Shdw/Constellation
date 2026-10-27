# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""CVE advisory feed connector — RSS/Atom fetcher + CVE-ID extractor.

Fetches a feed URL, parses its entries with stdlib xml.etree (no external
dep), pulls every CVE-XXXX-XXXX reference out of the title/description,
and returns normalised advisory records ready for INSERT.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from xml.etree import ElementTree as ET

import httpx

logger = logging.getLogger(__name__)

_TIMEOUT = 15.0
# Some RFC-1123 / RSS feeds use uppercase MIN/SEC initials, others use Atom
_ATOM_NS = {"a": "http://www.w3.org/2005/Atom"}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class FeedError(Exception):
    pass


@dataclass
class Advisory:
    advisory_ref: str
    title: str
    url: str | None
    summary: str | None
    published_at: datetime | None
    cve_ids: list[str] = field(default_factory=list)
    severity: str | None = None


def _parse_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    raw = raw.strip()
    # RSS uses RFC-822 (Mon, 03 Mar 2025 12:34:00 +0000), Atom uses ISO-8601
    try:
        dt = parsedate_to_datetime(raw)
        if dt:
            return (
                dt.astimezone(timezone.utc)
                if dt.tzinfo
                else dt.replace(tzinfo=timezone.utc)
            )
    except (TypeError, ValueError):
        pass
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    # Mirror the RFC-822 branch: a naive timestamp (vendor Atom feeds
    # without an offset, e.g. '2099-03-05T08:00:00') would otherwise be
    # bound to TIMESTAMPTZ via asyncpg's astimezone(utc), which silently
    # interprets it in the API container's local TZ — producing an N-hour
    # shift on any deployment where TZ != UTC.
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _extract_cves(*texts: str | None) -> list[str]:
    """Pull unique CVE IDs (uppercase) from one or more text blobs."""
    found: dict[str, None] = {}
    for t in texts:
        if not t:
            continue
        for m in _CVE_RE.findall(t):
            found[m.upper()] = None
    return list(found)


def _guess_severity(*texts: str | None) -> str | None:
    """Best-effort severity from advisory text (CERT-FR uses Gravité: critique etc.)."""
    blob = " ".join(t for t in texts if t).lower()
    # FR keywords first (CERT-FR), then English fallback
    if "critique" in blob or "critical" in blob:
        return "critical"
    if "élevé" in blob or "elevee" in blob or "élevée" in blob or "high" in blob:
        return "high"
    if "modér" in blob or "moder" in blob or "medium" in blob:
        return "medium"
    if "faible" in blob or "low" in blob:
        return "low"
    return None


def _parse_rss(root: ET.Element) -> list[Advisory]:
    items = root.findall(".//item")
    out: list[Advisory] = []
    for it in items:
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip() or None
        guid = (it.findtext("guid") or "").strip() or link or title
        desc = (it.findtext("description") or "").strip() or None
        pub = _parse_date(it.findtext("pubDate"))
        cves = _extract_cves(title, desc)
        out.append(
            Advisory(
                advisory_ref=guid,
                title=title,
                url=link,
                summary=desc,
                published_at=pub,
                cve_ids=cves,
                severity=_guess_severity(title, desc),
            )
        )
    return out


def _parse_atom(root: ET.Element) -> list[Advisory]:
    entries = root.findall("a:entry", _ATOM_NS)
    out: list[Advisory] = []
    for e in entries:
        title = (e.findtext("a:title", default="", namespaces=_ATOM_NS) or "").strip()
        # Atom links live in <link href="..."/>, often multiple. Prefer rel=alternate.
        link_el = e.find("a:link[@rel='alternate']", _ATOM_NS)
        if link_el is None:
            link_el = e.find("a:link", _ATOM_NS)
        link = link_el.get("href") if link_el is not None else None
        guid = (
            e.findtext("a:id", default="", namespaces=_ATOM_NS) or link or title
        ).strip()
        summary = (
            e.findtext("a:summary", default="", namespaces=_ATOM_NS)
            or e.findtext("a:content", default="", namespaces=_ATOM_NS)
            or ""
        ).strip() or None
        pub = _parse_date(
            e.findtext("a:published", default=None, namespaces=_ATOM_NS)
            or e.findtext("a:updated", default=None, namespaces=_ATOM_NS)
        )
        cves = _extract_cves(title, summary)
        out.append(
            Advisory(
                advisory_ref=guid,
                title=title,
                url=link,
                summary=summary,
                published_at=pub,
                cve_ids=cves,
                severity=_guess_severity(title, summary),
            )
        )
    return out


def parse_feed(body: bytes | str) -> list[Advisory]:
    """Parse a feed body — autodetects RSS vs Atom by root tag."""
    # Guard against XML entity-expansion ('billion laughs') / external-entity
    # attacks. Feed content comes from external servers and stdlib ElementTree
    # (expat) expands internal entities. Legitimate RSS/Atom never needs a DTD,
    # so reject any DOCTYPE/ENTITY declaration outright — cheaper and
    # dependency-free vs pulling in defusedxml.
    body_bytes = body if isinstance(body, bytes) else body.encode("utf-8", "replace")
    if re.search(rb"<!\s*(?:DOCTYPE|ENTITY)", body_bytes, re.IGNORECASE):
        raise FeedError("DTD/entity declarations are not permitted in feeds")
    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        raise FeedError(f"invalid XML: {e}") from e
    tag = root.tag.split("}")[-1].lower()
    if tag == "rss":
        return _parse_rss(root)
    if tag == "feed":
        return _parse_atom(root)
    # Sometimes RSS feeds wrap differently; <channel> at root is unusual but try.
    if root.find(".//item") is not None:
        return _parse_rss(root)
    raise FeedError(f"unknown root element: {tag}")


async def fetch_feed(
    url: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = _TIMEOUT,
) -> list[Advisory]:
    """Fetch + parse a feed. Caller may inject an httpx client for tests."""
    if client is None:
        async with httpx.AsyncClient(timeout=timeout) as c:
            return await fetch_feed(url, client=c, timeout=timeout)
    headers = {"User-Agent": "Constellation-CVE-Feed/1.0"}
    r = await client.get(url, headers=headers, follow_redirects=True)
    r.raise_for_status()
    return parse_feed(r.content)
