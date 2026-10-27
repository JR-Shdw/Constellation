# Honeytokens — runtime intrusion detection

## Concept

A honeytoken is an entry in `api_tokens` that **no legitimate client
ever uses**. Any authentication with such a token is therefore strong
evidence of an active intrusion or insider misuse.

When an attacker dumps the CMDB, lists tokens, or steals a config
file referencing one, the honey token looks like an attractive
target (e.g., `monitoring-collect-admin`). They use it.
Constellation fires an alert within milliseconds — but the auth
response itself is unchanged, so the attacker doesn't know.

## Detection paths

When a honey token authenticates, three things happen:

1. **CRITICAL log line** in the `cmdb.honey` logger
2. **Audit entry** with `action='honey_access'` (table `audit_log`)
3. **Matrix alert** to the `matrix_room_security` (or fallback
   `matrix_room_cve`) configured in `alert_settings`

Auth completes normally. Operator triages from the audit log + ping.

## Seeding

### UI — Tokens view

The "Create API Token" form has a yellow "Honeytoken (decoy)"
checkbox below the TTL selector. Tick it before submitting.

The visual styling is intentionally distinctive (orange tint) so
operators don't accidentally mark a real token as honey.

### API — POST `/api/v1/tokens`

```json
{
  "name": "monitoring-collect-admin",
  "permissions": {"collect": "w"},
  "description": "decoy",
  "is_honey": true
}
```

The plaintext token is returned once. Place it where attackers
might look — bait config files, fake backup notes, internal
misdirection — but **never** ship it to a legitimate consumer.

## Picking attractive names

Honey tokens only work if attackers want to use them. Mirror your
real ops naming.

**Good** — looks operationally important:
- `monitoring-collect-admin`
- `portainer-readonly`
- `backup-restic-status`
- `wazuh-agent-deploy`

**Bad** — obviously fake, attackers skip:
- `decoy-1`
- `honey-test`
- `do-not-use`

## Configuring the alert channel

The honey alert is sent via `notify._send_matrix` to the room
configured in `alert_settings`:

```sql
-- Set the security room (different from cve room ideally)
INSERT INTO alert_settings (key, value) VALUES
  ('matrix_room_security', '!XXXXXXXX:msg.example.com')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;
```

If `matrix_room_security` is empty, the alert falls back to
`matrix_room_cve`. Set `matrix_enabled='true'`, `matrix_url`, and
`matrix_token` for delivery to actually happen.

### Recommended setup

- Dedicated bot account on Matrix (`@cmdb-alerts:msg.example.com`)
- Dedicated room for honey/intrusion alerts, separate from CVE
  noise
- Matrix room different from your daily ops room — you don't want
  a CRITICAL signal lost in the queue

## Threat model

**What honey tokens catch**
- Compromise of a host where a token is stored
- Insider browsing the token list
- Backup/dump of `api_tokens` exfiltrated
- LLM-assisted reconnaissance trying interesting-looking tokens

**What they don't catch**
- Compromise of CMDB internals at rest (full DB dump and replay)
  — rotate everything if this happens
- Read of audit log itself (alert is reactive)

**Threshold for review** — every honey access is P1.
False positives are nearly impossible (no legitimate client knows
the names). Every hit is either:
- A genuine intrusion -> isolate, rotate all real tokens, audit
- A pentest -> confirm with the team
- An honest mistake -> rename or delete the honey, document

## Helper script

`tools/seed_honey.py` (when present) creates honey tokens via the
API — see the rhorizon counterpart for the pattern. CMDB tokens
can also be created via the standard Tokens UI with the new
checkbox.
