"""image_verify — the cosign consumer gate.

The gate must fail CLOSED for a trusted-namespace image when the verifier
(cosign) is unavailable: a missing binary must not silently disable signature
enforcement. An explicit override is for dev/test only.
"""

import pytest

import api.app.utils.image_verify as iv
from api.app.utils.image_verify import SignatureError, _key_for, verify_image

_TRUSTED = "gitea.example.com/shdw/rhorizon-api"


@pytest.mark.anyio
async def test_untrusted_namespace_is_noop():
    """No policy applies to an untrusted image — no error, no verification."""
    assert _key_for("alpine") is None
    await verify_image("alpine", "3.20")  # must not raise


@pytest.mark.anyio
async def test_trusted_namespace_no_cosign_fails_closed(monkeypatch):
    """Trusted image + no cosign + no override → refuse the pull."""
    monkeypatch.delenv("CMDB_ALLOW_UNVERIFIED_PULL", raising=False)
    monkeypatch.setattr(iv.shutil, "which", lambda _: None)
    assert _key_for(_TRUSTED) is not None
    with pytest.raises(SignatureError):
        await verify_image(_TRUSTED, "latest")


@pytest.mark.anyio
async def test_trusted_namespace_override_skips(monkeypatch):
    """The explicit dev override turns the missing-cosign case back into a skip."""
    monkeypatch.setattr(iv.shutil, "which", lambda _: None)
    monkeypatch.setenv("CMDB_ALLOW_UNVERIFIED_PULL", "1")
    await verify_image(_TRUSTED, "latest")  # must not raise
