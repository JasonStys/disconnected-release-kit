"""Jason Stys: independent staging/aggregate-cap, encrypted flag and trusted-floor rollback boundaries."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_staging_caps — line 41
# parameter: secret — line 41
# parameter: tmp_path — line 41
# definition: test_flags_and_directory — line 67
# parameter: archive — line 67
# parameter: policy — line 67
# parameter: trusted — line 67
# variable: mutated — line 69
# variable: offset — line 70
# variable: flags — line 71
# variable: files — line 75
# definition: test_zip_count_limits — line 81
# parameter: archive — line 81
# parameter: policy — line 81
# parameter: trusted — line 81
# definition: test_rollback_expiry_and_floor — line 90
# parameter: policy — line 91
# parameter: root — line 91
# parameter: secret — line 91
# parameter: trusted — line 91
# variable: one — line 95
# variable: two — line 96
# variable: check — line 97
# END CODE MAP

import struct
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import NOW, release
from test_bundle import contents

from drkit.bundle import collect, pack, read_file, verify
from drkit.contracts import Policy, Rejected
from drkit.deploy import activate, initialize, rollback


def test_staging_caps(tmp_path: Path, secret: bytes) -> None:
    """Bound empty-directory walks, file counts, bytes and directory depth before expensive work."""
    (tmp_path / "a").write_bytes(b"abc")
    with pytest.raises(Rejected, match="read cap"):
        read_file(tmp_path / "a", -2)
    with (
        patch("drkit.bundle.MAX_BUNDLE", 33),
        patch("drkit.bundle.MAX_FILE", 32),
        patch("drkit.bundle.read_file", return_value=b"abc"),
    ):
        with pytest.raises(Rejected, match="total"):
            collect(tmp_path)
        with pytest.raises(Rejected, match="total"):
            release(secret)
    with patch("drkit.bundle.MAX_ENTRIES", 3):
        with pytest.raises(Rejected, match="count"):
            collect(tmp_path)
    with patch("drkit.bundle.MAX_ENTRIES", 0):
        with pytest.raises(Rejected, match="directory entry"):
            collect(tmp_path)
    (tmp_path / "folder").mkdir()
    (tmp_path / "folder/a/b/c").mkdir(parents=True)
    with pytest.raises(Rejected, match="path"):
        collect(tmp_path)


def test_flags_and_directory(archive: bytes, trusted: bytes, policy: Policy) -> None:
    """Reject encrypted central-directory flags and actual directory ZIP entries."""
    mutated = bytearray(archive)
    offset = mutated.find(b"PK\x01\x02")
    flags = struct.unpack_from("<H", mutated, offset + 8)[0]
    struct.pack_into("<H", mutated, offset + 8, flags | 1)
    with pytest.raises(Rejected, match="encrypted"):
        verify(bytes(mutated), trusted, policy)
    files = contents(archive)
    files["payload/dir/"] = b""
    with pytest.raises(Rejected, match="nonregular"):
        verify(pack(files), trusted, policy)


def test_zip_count_limits(archive: bytes, trusted: bytes, policy: Policy) -> None:
    """Enforce member count and per-manifest cap independent of whole-archive cap."""
    with pytest.raises(Rejected, match="entry count"):
        verify(pack({"manifest.json": b"x"}), trusted, policy)
    with patch("drkit.bundle.MAX_MANIFEST", 300):
        with pytest.raises(Rejected, match="entry exceeds"):
            verify(archive, trusted, policy)


def test_rollback_expiry_and_floor(
    root: Path, secret: bytes, trusted: bytes, policy: Policy
) -> None:
    """Explicit rollback does not bypass independent expiry or operator minimum-sequence policy."""
    initialize(root)
    one = activate(root, release(secret), trusted, policy, None)
    two = activate(root, release(secret, 2), trusted, policy, one["current"])
    for check in (
        Policy(policy.product, policy.target, NOW + 3600),
        Policy(policy.product, policy.target, NOW, 2),
    ):
        with pytest.raises(Rejected):
            rollback(root, one["current"], two["current"], trusted, check)
