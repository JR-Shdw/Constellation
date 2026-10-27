<!--
SPDX-License-Identifier: Apache-2.0
Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
-->

# Git hooks (Option B — shell + Docker fallback)

This directory ships a `pre-commit` hook that runs the same checks as the
Woodpecker `validate` pipeline locally, before each commit:

1. `ruff check` on staged Python files
2. `ruff format --check` on staged Python files
3. `detect-secrets` vs `.secrets.baseline` on the whole working tree

Versions are pinned in [`versions.env`](../../versions.env)
(`RUFF_VERSION`, `DETECT_SECRETS_VERSION`).

## Activation (one command, no install)

```bash
make hooks-install
# equivalent to:  git config core.hooksPath scripts/git-hooks
```

That's it. No `pip install`, no `pre-commit` framework. Per-repo configuration,
no system-wide change.

## How the hook decides its execution mode

The hook auto-detects available tooling, in this order:

| Priority | Mode | Requirements | Speed |
|---|---|---|---|
| 1 | local `PATH` | `ruff` + `detect-secrets` in your `$PATH` | fast (~1s) |
| 2 | project venv | `.venv/bin/ruff` + `.venv/bin/detect-secrets` | fast (~1s) |
| 3 | container | `docker` or `podman` available | slow first run (~30s), faster after |
| fallback | — | none of the above | fails with a clear message |

You don't have to choose — whichever path is available, it works.

## Bypass (use sparingly)

```bash
git commit --no-verify -m "..."
```

CI will still catch what you skip — `--no-verify` only gains you ~3-5s and
risks pushing a leak or lint error to the remote.

## Alternative: Option A (pre-commit framework)

If you prefer the standard `pre-commit` framework (auto-update via
`pre-commit autoupdate`, per-hook skip via `SKIP=ruff`, etc.):

```bash
pip install pre-commit
pre-commit install
```

The `.pre-commit-config.yaml` at the repo root mirrors the same three checks.
Both options are kept in sync — when adding a hook, update both files.

## Uninstall

```bash
git config --unset core.hooksPath
```

This restores the default `.git/hooks/` directory.
