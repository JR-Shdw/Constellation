#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Seed honey (or normal) API tokens via the cmdb API.

Usage:
    export CMDB_URL=https://cmdb.internal
    export CMDB_TOKEN=cmdb_admin_xxxxx

    # Honey token (decoy — any auth fires CRITICAL alert)
    ./tools/seed_honey.py --name monitoring-collect-admin \
        --perms '{"collect":"w"}' --honey

    # Same without --honey creates a regular token.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def main() -> None:
    p = argparse.ArgumentParser(
        description="Seed cmdb api_tokens, optionally as honeytokens."
    )
    p.add_argument("--name", required=True)
    p.add_argument("--perms", required=True,
                   help='JSON, e.g. \'{"collect":"w"}\'')
    p.add_argument("--description")
    p.add_argument("--expires", help="ISO datetime (optional)")
    p.add_argument("--honey", action="store_true",
                   help="Mark token as decoy — any auth fires alert")
    args = p.parse_args()

    if not os.environ.get("CMDB_URL") or not os.environ.get("CMDB_TOKEN"):
        sys.exit("error: set CMDB_URL and CMDB_TOKEN env vars")

    body = {"name": args.name, "permissions": json.loads(args.perms)}
    if args.description:
        body["description"] = args.description
    if args.expires:
        body["expires_at"] = args.expires
    if args.honey:
        body["is_honey"] = True

    url = os.environ["CMDB_URL"].rstrip("/") + "/api/v1/tokens"
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {os.environ['CMDB_TOKEN']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"HTTP {e.code}: {e.read().decode(errors='replace')}\n")
        sys.exit(1)

    flag = " (HONEY)" if args.honey else ""
    print(f"created token '{args.name}'{flag}")
    print(f"  token: {d.get('token', '<not returned>')}")
    print("  ^ store it now, can't be retrieved later")
    if args.honey:
        print("  HONEY: do NOT distribute. Place where an attacker might")
        print("         find it (bait config, fake backup share).")


if __name__ == "__main__":
    main()
