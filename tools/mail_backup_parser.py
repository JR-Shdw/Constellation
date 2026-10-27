#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Parse backup notification emails and POST to CMDB API.

Usage:
    echo "mail content" | mail_backup_parser.py
    mail_backup_parser.py /path/to/mail.eml

Environment:
    CMDB_API            — API base URL (default: http://10.0.0.1:8000)
    CMDB_COLLECT_TOKEN  — Bearer token
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from email import message_from_string

import requests

CMDB_API = os.environ.get("CMDB_API", "http://10.0.0.1:8000")
CMDB_TOKEN = os.environ.get("CMDB_COLLECT_TOKEN", "")


def parse_mail(raw: str) -> dict:
    msg = message_from_string(raw)
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body = payload.decode(errors="replace")
                break
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="replace")

    subject = msg.get("subject", "")
    sender = msg.get("from", "")

    status = (
        "success"
        if re.search(r"success|complet|ok|done", body, re.I)
        else "failure"
    )
    hostname_m = re.search(r"host[:\s]+([a-zA-Z0-9._-]+)", body, re.I)
    duration_m = re.search(r"(\d+)\s*(s|sec|seconds|mn|min|minutes)", body, re.I)

    return {
        "hostname": hostname_m.group(1) if hostname_m else sender[:80],
        "repo_name": subject[:80] or "mail-backup",
        "repo_path": "",
        "status": status,
        "duration_secs": int(duration_m.group(1)) if duration_m else 0,
        "size_added": 0,
        "size_total": 0,
        "files_new": 0,
        "files_changed": 0,
        "files_unmodified": 0,
        "snapshots_total": 0,
        "error_msg": body[:500] if status == "failure" else "",
        "source": "mail",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "raw": {"subject": subject, "body": body[:2000]},
    }


if __name__ == "__main__":
    raw = sys.stdin.read() if not sys.argv[1:] else open(sys.argv[1]).read()
    payload = parse_mail(raw)
    r = requests.post(
        f"{CMDB_API}/api/v1/backup/report",
        headers={"Authorization": f"Bearer {CMDB_TOKEN}"},
        json=payload,
        timeout=10,
    )
    print(f"Posted: {r.status_code}")
