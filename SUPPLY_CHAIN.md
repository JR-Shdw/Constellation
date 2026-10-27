# Supply-chain hardening (PyPI / SLSA)

PyPI account-takeover and malicious-release attacks are a live, growing vector.
This repo treats every Python dependency — runtime, tooling, and the tools image
— as untrusted until its exact artifact is verified by hash.

## What is enforced

| Control | Where | Effect |
|---|---|---|
| **Hash-locked deps** (`--hash=sha256`) | `api/requirements.lock`, `requirements-dev.txt`, `tools/requirements.lock` | a substituted/tampered artifact cannot install — pip rejects a hash mismatch |
| **`pip install --require-hashes`** | api + tools Dockerfiles, `.woodpecker/validate.yml`, `bench.yml`, local gate | no unhashed/unpinned package can slip in (incl. transitive) |
| **Pinned, CVE-fixed pip** (`pip==26.1.2`) | every install step | closes the 5 advisories in the base image's pip 25.0.1 (incl. CVE-2025-8869, install-time) |
| **`pip-audit -r api/requirements.lock`** | `validate.yml` lint step | build **fails** on any fixable CVE in the shipped deps |
| **Bandit SAST** | `validate.yml` | build fails on HIGH-severity findings |
| **detect-secrets** baseline | `validate.yml` | blocks new secrets |

The lockfiles are the source of truth for *what installs*; the `.in` /
`requirements.txt` files are the human-edited *intent*.

## Bumping a dependency

Edit the version in `api/requirements.txt`, `requirements-dev.in`, or
`tools/requirements.in`, then:

```bash
make deps-update     # rehash all locks (--generate-hashes) + pip-audit them
git diff api/requirements.lock requirements-dev.txt tools/requirements.lock
git add … && commit  # only if the audit was green
```

`make deps-update` = `deps-lock` (rehash) + `deps-audit` (scan); it fails if a
bumped version pulls a package with a known vulnerability, so a bad bump never
gets locked in. The raw equivalent (no make):

```bash
pip install pip-tools
pip-compile --generate-hashes --output-file=api/requirements.lock      api/requirements.txt
pip-compile --generate-hashes --strip-extras \
            --output-file=requirements-dev.txt                          requirements-dev.in
pip-compile --generate-hashes --output-file=tools/requirements.lock     tools/requirements.in
```

Then verify nothing regressed:

```bash
pip-audit -r api/requirements.lock        # must report 0 fixable CVEs
# CI re-runs the full gate under --require-hashes
```

Keep `ruff` / `detect-secrets` versions in `requirements-dev.in` in lockstep
with `versions.env` (CI lint parity).

## Next frontier (not yet implemented)

- **Provenance / attestation verification (PEP 740 / Sigstore).** PyPI now serves
  publish attestations for packages using Trusted Publishing; `pip` does not
  verify them by default. A `pypi-attestations`-based gate would raise this from
  "integrity by hash" to "verified provenance" — the logical extension of the
  cosign consumer gate already used for container images
  (`api/app/utils/image_verify.py`).
- **Pre-baked gate image** (deps installed at image-build time, no `pip` at run
  time) to remove install-time network entirely.
