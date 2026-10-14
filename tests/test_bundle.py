"""Jason Stys: authenticated content, deterministic layout, malicious ZIPs and no-self-trust regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: contents — line 103
# parameter: archive — line 103
# variable: container — line 105
# variable: member — line 107
# definition: resign — line 111
# parameter: files — line 111
# parameter: secret — line 111
# definition: test_happy_and_determinism — line 119
# parameter: archive — line 120
# parameter: policy — line 120
# parameter: secret — line 120
# parameter: trusted — line 120
# variable: result — line 124
# definition: test_tampering — line 147
# parameter: archive — line 148
# parameter: mutation — line 148
# parameter: policy — line 148
# parameter: trusted — line 148
# variable: files — line 151
# definition: test_wrong_key — line 174
# parameter: archive — line 174
# parameter: policy — line 174
# variable: public — line 176
# definition: test_policy_failure — line 193
# parameter: archive — line 193
# parameter: policy — line 193
# parameter: trusted — line 193
# definition: test_archive_profile — line 214
# parameter: archive — line 215
# parameter: kind — line 215
# parameter: policy — line 215
# parameter: trusted — line 215
# variable: files — line 218
# variable: buffer — line 219
# variable: container — line 221
# variable: data — line 222
# variable: name — line 222
# variable: info — line 223
# attribute: external_attr — line 224
# attribute: compress_type — line 229
# variable: candidate — line 241
# variable: container — line 243
# variable: data — line 244
# variable: name — line 244
# variable: info — line 245
# attribute: external_attr — line 246
# attribute: comment — line 248
# variable: candidate — line 249
# variable: candidate — line 251
# variable: candidate — line 253
# variable: candidate — line 255
# variable: candidate — line 259
# variable: candidate — line 261
# definition: test_authenticated_semantic_tampering — line 266
# parameter: archive — line 267
# parameter: policy — line 267
# parameter: secret — line 267
# parameter: trusted — line 267
# variable: files — line 270
# variable: valid — line 271
# variable: body — line 272
# parameter: item — line 274
# variable: body — line 278
# parameter: item — line 283
# variable: files — line 286
# variable: body — line 288
# definition: test_source_and_limits — line 295
# parameter: secret — line 295
# parameter: tmp_path — line 295
# definition: test_archive_fuzz — line 346
# parameter: data — line 346
# definition: test_link_checks — line 352
# parameter: tmp_path — line 352
# END CODE MAP

import io
import json
import stat
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import NOW, release
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from drkit.bundle import DOMAIN, build, collect, pack, read_file, verify
from drkit.contracts import (
    MAX_BUNDLE,
    MAX_FILE,
    Policy,
    Rejected,
    canonical,
    manifest,
    sha,
)


def contents(archive: bytes) -> dict[str, bytes]:
    """Read only test-generated bounded containers for controlled malicious mutations."""
    with zipfile.ZipFile(io.BytesIO(archive)) as container:
        return {
            member.filename: container.read(member) for member in container.infolist()
        }


def resign(files: dict[str, bytes], secret: bytes) -> bytes:
    """Re-sign controlled malformed test manifests to test semantic validation after valid authentication."""
    files["manifest.sig"] = Ed25519PrivateKey.from_private_bytes(secret).sign(
        DOMAIN + files["manifest.json"]
    )
    return pack(files)


def test_happy_and_determinism(
    archive: bytes, secret: bytes, trusted: bytes, policy: Policy
) -> None:
    """The same inputs/key produce byte-identical archives and exact authenticated payloads."""
    assert archive == release(secret)
    result = verify(archive, trusted, policy)
    assert (
        result.digest == sha(archive)
        and result.files["payload/app.py"] == b'print("synthetic")\n'
    )
    assert archive != release(secret, 2)
    assert result.metadata["sequence"] == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "payload",
        "signature",
        "manifest",
        "short-signature",
        "missing-signature",
        "extra",
        "missing-payload",
        "inventory",
        "embedded-key",
    ],
)
def test_tampering(
    mutation: str, archive: bytes, trusted: bytes, policy: Policy
) -> None:
    """Each independently tampered component fails closed even if ZIP checksums are recomputed."""
    files = contents(archive)
    if mutation == "payload":
        files["payload/app.py"] += b"# changed"
    elif mutation == "signature":
        files["manifest.sig"] = b"x" * 64
    elif mutation == "manifest":
        files["manifest.json"] += b" "
    elif mutation == "short-signature":
        files["manifest.sig"] = b"x"
    elif mutation == "missing-signature":
        del files["manifest.sig"]
    elif mutation == "extra":
        files["payload/extra"] = b"extra"
    elif mutation == "missing-payload":
        del files["payload/app.py"]
    elif mutation == "inventory":
        files["inventory.spdx.json"] = b"{}"
    else:
        files["trust.pub"] = trusted
    with pytest.raises(Rejected):
        verify(pack(files), trusted, policy)


def test_wrong_key(archive: bytes, policy: Policy) -> None:
    """An attacker-supplied key can never replace the external trusted verifier key."""
    public = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(Rejected, match="signature"):
        verify(archive, public, policy)
    with pytest.raises(Rejected, match="size"):
        verify(archive, b"x", policy)


@pytest.mark.parametrize(
    "policy",
    [
        Policy("other", "portable-source", NOW),
        Policy("demo-service", "other", NOW),
        Policy("demo-service", "portable-source", NOW - 2),
        Policy("demo-service", "portable-source", NOW + 3600),
        Policy("demo-service", "portable-source", NOW, 2),
    ],
)
def test_policy_failure(archive: bytes, trusted: bytes, policy: Policy) -> None:
    """Mismatch, future, expiry and trusted floor reject cryptographically valid archives."""
    with pytest.raises(Rejected):
        verify(archive, trusted, policy)


@pytest.mark.parametrize(
    "kind",
    [
        "duplicate",
        "symlink",
        "compressed",
        "comment",
        "prefix",
        "suffix",
        "broken",
        "missing-manifest",
        "oversized",
        "crc",
    ],
)
def test_archive_profile(
    kind: str, archive: bytes, trusted: bytes, policy: Policy
) -> None:
    """Reject dangerous member types, resource caps, ambiguous metadata and damaged checksums."""
    files = contents(archive)
    buffer = io.BytesIO()
    if kind in {"duplicate", "symlink", "compressed", "oversized"}:
        with zipfile.ZipFile(buffer, "w") as container:
            for name, data in files.items():
                info = zipfile.ZipInfo(name)
                info.external_attr = (
                    stat.S_IFLNK
                    if kind == "symlink" and name.startswith("payload/")
                    else stat.S_IFREG | 0o644
                ) << 16
                info.compress_type = (
                    zipfile.ZIP_DEFLATED if kind == "compressed" else zipfile.ZIP_STORED
                )
                container.writestr(
                    info,
                    b"x" * (MAX_FILE + 1)
                    if kind == "oversized" and name.startswith("payload/")
                    else data,
                )
            if kind == "duplicate":
                with pytest.warns(UserWarning, match="Duplicate name"):
                    container.writestr("payload/app.py", b"duplicate")
        candidate = buffer.getvalue()
    elif kind == "comment":
        with zipfile.ZipFile(buffer, "w") as container:
            for name, data in files.items():
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                container.writestr(info, data)
            container.comment = b"untrusted comment"
        candidate = buffer.getvalue()
    elif kind == "prefix":
        candidate = b"prefix" + archive
    elif kind == "suffix":
        candidate = archive + b"suffix"
    elif kind == "broken":
        candidate = b"not a zip"
    elif kind == "missing-manifest":
        del files["manifest.json"]
        files["payload/extra"] = b"x"
        candidate = pack(files)
    else:
        candidate = archive.replace(b'print("synthetic")', b'print("malicious")')
    with pytest.raises(Rejected):
        verify(candidate, trusted, policy)


def test_authenticated_semantic_tampering(
    archive: bytes, secret: bytes, trusted: bytes, policy: Policy
) -> None:
    """A valid signature cannot admit invalid shapes, case collisions, path ancestors or inventory lies."""
    files = contents(archive)
    valid = json.loads(files["manifest.json"])
    body = json.loads(json.dumps(valid))
    body["files"].append({"path": "payload/App.py", "size": 0, "sha256": sha(b"")})
    body["files"].sort(key=lambda item: item["path"])
    files["manifest.json"] = canonical(body)
    with pytest.raises(Rejected, match="colliding"):
        verify(resign(files, secret), trusted, policy)
    body = json.loads(json.dumps(valid))
    body["files"] += [
        {"path": "payload/a", "size": 0, "sha256": sha(b"")},
        {"path": "payload/a/b/c", "size": 0, "sha256": sha(b"")},
    ]
    body["files"].sort(key=lambda item: item["path"])
    with pytest.raises(Rejected, match="directory"):
        manifest(canonical(body), policy)
    files = contents(archive)
    files["inventory.spdx.json"] = b"{}"
    body = json.loads(files["manifest.json"])
    body["files"][0] = {"path": "inventory.spdx.json", "size": 2, "sha256": sha(b"{}")}
    files["manifest.json"] = canonical(body)
    with pytest.raises(Rejected, match="inventory mismatch"):
        verify(resign(files, secret), trusted, policy)


def test_source_and_limits(tmp_path: Path, secret: bytes) -> None:
    """Collect explicit source only and fail rather than silently skip malformed local files."""
    (tmp_path / "a.py").write_bytes(b"# demo")
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir/b.txt").write_bytes(b"nested")
    assert collect(tmp_path) == {
        "payload/a.py": b"# demo",
        "payload/subdir/b.txt": b"nested",
    }
    with pytest.raises(Rejected):
        read_file(tmp_path / "a.py", 1)
    with pytest.raises(Rejected):
        read_file(tmp_path / "missing")
    with pytest.raises(Rejected):
        collect(tmp_path / "missing")
    (tmp_path / "private.key").write_bytes(b"test")
    with pytest.raises(Rejected, match="private"):
        collect(tmp_path)
    with pytest.raises(Rejected, match="count"):
        build(
            {},
            secret,
            product="demo-service",
            version="1.0.0",
            sequence=1,
            target="portable-source",
            created=NOW,
            expires=NOW + 1,
            revision="a" * 40,
        )
    with pytest.raises(Rejected, match="key"):
        build(
            {"payload/x": b""},
            b"x",
            product="demo-service",
            version="1.0.0",
            sequence=1,
            target="portable-source",
            created=NOW,
            expires=NOW + 1,
            revision="a" * 40,
        )
    with patch("drkit.bundle.MAX_BUNDLE", 10):
        with pytest.raises(Rejected):
            release(secret)
    with pytest.raises(Rejected):
        verify(b"x" * (MAX_BUNDLE + 1), b"x" * 32, Policy("demo", "portable", NOW))


@given(st.binary(max_size=4096))
@settings(max_examples=100, deadline=None)
def test_archive_fuzz(data: bytes) -> None:
    """Random bounded archive bytes never escape controlled rejection or execute code."""
    with pytest.raises(Rejected):
        verify(data, b"x" * 32, Policy("demo", "portable", NOW))


def test_link_checks(tmp_path: Path) -> None:
    """Simulate link/junction decisions portably; real Linux symlink cases are also exercised."""
    (tmp_path / "a.py").write_bytes(b"x")
    with patch.object(Path, "is_junction", return_value=True):
        with pytest.raises(Rejected):
            collect(tmp_path)
        with pytest.raises(Rejected):
            read_file(tmp_path / "a.py")
    with patch.object(Path, "is_symlink", side_effect=[False, True]):
        with pytest.raises(Rejected):
            collect(tmp_path)
