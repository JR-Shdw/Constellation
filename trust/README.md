# Trust roots — pinned upstream signing keys

Public keys we trust to sign images / artifacts that cmdb pulls or
verifies. Each file is committed to git; bumping requires a deliberate
commit (the chain of trust survives a registry compromise but not
a git compromise).

| File | Source | Used by |
|---|---|---|
| `rhorizon-cosign.pub` | https://gitea.example.com/shdw/rhorizon/raw/branch/main/cosign.pub | `image_verify.py` consumer gate (Phase 5 of rhorizon's supply-chain plan) — refuse to `pull_image` an image in `gitea.example.com/shdw/rhorizon-*` whose cosign signature doesn't match. |

## Verifying a key file matches the upstream

```bash
diff <(curl -fsSL https://gitea.example.com/shdw/rhorizon/raw/branch/main/cosign.pub) \
     trust/rhorizon-cosign.pub
```

Empty output ⇒ same bytes ⇒ trust still anchored.

## Rotating

If rhorizon's signing key is rotated, the new `cosign.pub` ships in
the rhorizon release notes. Replace `trust/rhorizon-cosign.pub` here
in a single commit, run the diff above, and let CI re-verify the next
deploy.
