"""Jason Stys: atomic pointer, crash residue, CAS, rollback and immutable retained-byte regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_activation_and_rollback — line 66
# parameter: policy — line 67
# parameter: root — line 67
# parameter: secret — line 67
# parameter: trusted — line 67
# variable: one — line 71
# variable: two — line 72
# variable: old — line 73
# definition: test_lock_and_interruption — line 87
# parameter: archive — line 88
# parameter: policy — line 88
# parameter: root — line 88
# parameter: trusted — line 88
# definition: test_commit_pointer_failure — line 105
# parameter: archive — line 106
# parameter: policy — line 106
# parameter: root — line 106
# parameter: trusted — line 106
# definition: test_retained_validation — line 119
# parameter: archive — line 120
# parameter: mutation — line 120
# parameter: policy — line 120
# parameter: root — line 120
# parameter: trusted — line 120
# variable: active — line 124
# variable: directory — line 125
# variable: renamed — line 133
# variable: directory — line 135
# definition: test_state_shape — line 164
# parameter: root — line 164
# parameter: value — line 164
# definition: test_history_cap — line 172
# parameter: policy — line 172
# parameter: root — line 172
# parameter: secret — line 172
# parameter: trusted — line 172
# definition: test_real_symlink — line 187
# parameter: archive — line 188
# parameter: policy — line 188
# parameter: root — line 188
# parameter: trusted — line 188
# variable: active — line 192
# variable: directory — line 193
# END CODE MAP

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import release

from drkit.contracts import Policy, Rejected, canonical
from drkit.deploy import (
    activate,
    initialize,
    locked,
    rollback,
    state,
    validate_installed,
)


def test_activation_and_rollback(
    root: Path, secret: bytes, trusted: bytes, policy: Policy
) -> None:
    """Activate two releases, explicitly roll back, preserve the floor and retain both releases."""
    initialize(root)
    one = activate(root, release(secret), trusted, policy, None)
    two = activate(root, release(secret, 2), trusted, policy, one["current"])
    old = rollback(root, one["current"], two["current"], trusted, policy)
    assert old["current"] == one["current"] and old["highest_sequence"] == 2
    assert len(list((root / "releases").iterdir())) == 2
    with pytest.raises(Rejected, match="sequence"):
        activate(root, release(secret, 2), trusted, policy, one["current"])
    with pytest.raises(Rejected, match="changed"):
        activate(root, release(secret, 3), trusted, policy, two["current"])
    with pytest.raises(Rejected, match="selection"):
        rollback(root, "../anything", one["current"], trusted, policy)
    with pytest.raises(Rejected):
        initialize(root)
    assert state(root) == old


def test_lock_and_interruption(
    root: Path, archive: bytes, trusted: bytes, policy: Policy
) -> None:
    """Nested concurrent admission fails; pointer stays unchanged after interrupted stage/commit."""
    initialize(root)
    with locked(root):
        with pytest.raises(Rejected, match="locked"):
            activate(root, archive, trusted, policy, None)
    with patch("drkit.deploy.commit", side_effect=OSError("simulated IO")):
        with pytest.raises(OSError):
            activate(root, archive, trusted, policy, None)
    assert state(root)["current"] is None
    assert not (root / "operation.lock").exists()
    assert len(list((root / "releases").iterdir())) == 1
    with pytest.raises(Rejected, match="already exists"):
        activate(root, archive, trusted, policy, None)


def test_commit_pointer_failure(
    root: Path, archive: bytes, trusted: bytes, policy: Policy
) -> None:
    """Interrupted pointer replacement leaves original valid state and inspectable pending bytes."""
    initialize(root)
    with patch("drkit.deploy.os.replace", side_effect=OSError("test crash")):
        with pytest.raises(OSError):
            activate(root, archive, trusted, policy, None)
    assert state(root)["current"] is None and (root / "state.pending").is_file()


@pytest.mark.parametrize(
    "mutation", ["bytes", "extra", "missing", "archive", "link", "special"]
)
def test_retained_validation(
    mutation: str, root: Path, archive: bytes, trusted: bytes, policy: Policy
) -> None:
    """A rollback cannot activate modified, mismatched or incomplete installed bytes."""
    initialize(root)
    active = activate(root, archive, trusted, policy, None)
    directory = root / "releases" / active["current"]
    if mutation == "bytes":
        (directory / "payload/app.py").write_bytes(b"changed")
    elif mutation == "extra":
        (directory / "extra.txt").write_bytes(b"x")
    elif mutation == "missing":
        (directory / "payload/app.py").unlink()
    elif mutation == "archive":
        renamed = directory.with_name("b" * 64)
        directory.rename(renamed)
        directory = renamed
    elif mutation == "link":
        with patch.object(Path, "is_symlink", side_effect=[False, False, False, True]):
            with pytest.raises(Rejected):
                validate_installed(directory, trusted, policy)
        return
    else:
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "is_dir", side_effect=[True, False]),
        ):
            with pytest.raises(Rejected):
                validate_installed(directory, trusted, policy)
        return
    with pytest.raises(Rejected):
        validate_installed(directory, trusted, policy)


@pytest.mark.parametrize(
    "value",
    [
        {},
        [],
        {"schema": True, "current": None, "highest_sequence": 0, "history": []},
        {"schema": 1, "current": None, "highest_sequence": True, "history": []},
        {"schema": 1, "current": None, "highest_sequence": 0, "history": ["../a"]},
        {"schema": 1, "current": "a" * 64, "highest_sequence": 0, "history": []},
    ],
)
def test_state_shape(value: object, root: Path) -> None:
    """Reject malformed owner-state path references instead of trusting arbitrary names."""
    initialize(root)
    (root / "state.json").write_bytes(canonical(value))
    with pytest.raises(Rejected):
        state(root)


def test_history_cap(root: Path, secret: bytes, trusted: bytes, policy: Policy) -> None:
    """Bound state history without deleting retained releases automatically."""
    initialize(root)
    (root / "state.json").write_bytes(
        canonical(
            dict(schema=1, current=None, highest_sequence=0, history=["a" * 64] * 1000)
        )
    )
    with pytest.raises(Rejected, match="cap"):
        activate(root, release(secret), trusted, policy, None)


@pytest.mark.skipif(
    os.name == "nt", reason="Windows junction/link privilege is not assumed"
)
def test_real_symlink(
    root: Path, archive: bytes, trusted: bytes, policy: Policy
) -> None:
    """A real Linux/macOS installed symlink fails revalidation."""
    initialize(root)
    active = activate(root, archive, trusted, policy, None)
    directory = root / "releases" / active["current"]
    (directory / "payload/link").symlink_to("app.py")
    with pytest.raises(Rejected, match="links"):
        validate_installed(directory, trusted, policy)
