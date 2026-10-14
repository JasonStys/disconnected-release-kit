"""Jason Stys: owned-root staging, atomic activation, compare-and-swap and explicit non-destructive rollback."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: regular_dir — line 72
# parameter: path — line 72
# definition: initialize — line 80
# parameter: root — line 80
# definition: state — line 90
# parameter: root — line 90
# variable: value — line 94
# variable: item — line 111
# definition: locked — line 125
# parameter: root — line 125
# variable: lock — line 128
# variable: descriptor — line 130
# definition: commit — line 140
# parameter: root — line 140
# parameter: value — line 140
# variable: temporary — line 142
# variable: stream — line 143
# definition: validate_installed — line 150
# parameter: directory — line 150
# parameter: policy — line 150
# parameter: trusted — line 150
# variable: bundle — line 153
# variable: actual — line 155
# variable: path — line 156
# variable: name — line 162
# definition: activate — line 175
# parameter: archive — line 176
# parameter: expected — line 176
# parameter: policy — line 176
# parameter: root — line 176
# parameter: trusted — line 176
# variable: old — line 180
# variable: bundle — line 182
# variable: destination — line 188
# variable: data — line 195
# variable: name — line 195
# variable: target — line 196
# variable: new — line 200
# definition: rollback — line 210
# parameter: expected — line 211
# parameter: policy — line 211
# parameter: root — line 211
# parameter: target — line 211
# parameter: trusted — line 211
# variable: old — line 215
# variable: new — line 223
# END CODE MAP

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast

from drkit.bundle import Verified, read_file, verify
from drkit.contracts import (
    DIGEST,
    MAX_BUNDLE,
    Policy,
    Rejected,
    canonical,
    decode,
    integer,
    require,
)


def regular_dir(path: Path) -> None:
    """Require a trusted ordinary directory; this is not a hostile-host filesystem sandbox."""
    require(
        path.is_dir() and not path.is_symlink() and not path.is_junction(),
        "regular deployment directory required",
    )


def initialize(root: Path) -> None:
    """Create only a new explicit owned deployment directory, never take over existing contents."""
    require(not root.exists(), "deployment root already exists")
    root.mkdir(mode=0o700)
    (root / "releases").mkdir(mode=0o700)
    (root / "state.json").write_bytes(
        canonical(dict(schema=1, current=None, highest_sequence=0, history=[]))
    )


def state(root: Path) -> dict[str, Any]:
    """Read bounded local owner-trusted state; validate digest names before filesystem use."""
    regular_dir(root)
    regular_dir(root / "releases")
    value = decode(read_file(root / "state.json"))
    require(
        isinstance(value, dict)
        and set(value) == {"schema", "current", "highest_sequence", "history"},
        "invalid deployment state",
    )
    require(
        type(value["schema"]) is int
        and value["schema"] == 1
        and integer(value["highest_sequence"], 0, 2**31 - 1),
        "invalid state version/sequence",
    )
    require(
        isinstance(value["history"], list)
        and len(value["history"]) <= 1000
        and all(
            isinstance(item, str) and DIGEST.fullmatch(item)
            for item in value["history"]
        ),
        "invalid state history",
    )
    require(
        value["current"] is None
        or isinstance(value["current"], str)
        and value["current"] in value["history"],
        "invalid active digest",
    )
    return cast(dict[str, Any], value)


@contextmanager
def locked(root: Path) -> Iterator[None]:
    """Own one exclusive lock; interrupted locks require manual inspection, not automatic takeover."""
    regular_dir(root)
    lock = root / "operation.lock"
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as error:
        raise Rejected("deployment is locked") from error
    os.close(descriptor)
    try:
        yield
    finally:
        lock.unlink()


def commit(root: Path, value: dict[str, Any]) -> None:
    """Flush a new state file and atomically replace its pointer; not a full power-loss durability guarantee."""
    temporary = root / "state.pending"
    with temporary.open("xb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, root / "state.json")


def validate_installed(directory: Path, trusted: bytes, policy: Policy) -> Verified:
    """Reauthenticate retained archive and verify the exact installed file tree before selecting it."""
    regular_dir(directory)
    bundle = verify(read_file(directory / "bundle.zip", MAX_BUNDLE), trusted, policy)
    require(directory.name == bundle.digest, "retained archive digest mismatch")
    actual: set[str] = set()
    for path in directory.rglob("*"):
        require(
            not path.is_symlink() and not path.is_junction(),
            "installed links are forbidden",
        )
        if path.is_file():
            name = path.relative_to(directory).as_posix()
            actual.add(name)
            if name != "bundle.zip":
                require(
                    name in bundle.files and read_file(path) == bundle.files[name],
                    "installed file mismatch",
                )
        else:
            require(path.is_dir(), "nonregular installed entry")
    require(actual == set(bundle.files) | {"bundle.zip"}, "installed file set mismatch")
    return bundle


def activate(
    root: Path, archive: bytes, trusted: bytes, policy: Policy, expected: str | None
) -> dict[str, Any]:
    """Stage an authenticated higher-sequence release; CAS pointer change only after full revalidation."""
    with locked(root):
        old = state(root)
        require(old["current"] == expected, "active digest changed")
        bundle = verify(archive, trusted, policy)
        require(
            bundle.metadata["sequence"] > old["highest_sequence"],
            "normal activation cannot downgrade/reuse sequence",
        )
        require(len(old["history"]) < 1000, "deployment history cap reached")
        destination = root / "releases" / bundle.digest
        require(
            not destination.exists(),
            "release directory already exists; inspect interrupted staging",
        )
        destination.mkdir(mode=0o700)
        (destination / "bundle.zip").write_bytes(bundle.archive)
        for name, data in bundle.files.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            target.write_bytes(data)
        validate_installed(destination, trusted, policy)
        new = dict(
            schema=1,
            current=bundle.digest,
            highest_sequence=bundle.metadata["sequence"],
            history=[*old["history"], bundle.digest],
        )
        commit(root, new)
        return new


def rollback(
    root: Path, target: str, expected: str, trusted: bytes, policy: Policy
) -> dict[str, Any]:
    """Explicit retained-target CAS rollback; preserve high-water sequence and reject invalid/expired content."""
    with locked(root):
        old = state(root)
        require(
            old["current"] == expected
            and target in old["history"]
            and target != expected,
            "invalid rollback selection/CAS",
        )
        validate_installed(root / "releases" / target, trusted, policy)
        new = {**old, "current": target}
        commit(root, new)
        return new
