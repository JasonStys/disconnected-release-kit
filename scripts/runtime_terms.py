"""Verify captured original crypto/Rust terms against the actual installed wheel on each build OS. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: INVENTORY_SHA256 — line 58
# variable: COMPILER — line 59
# definition: bounded — line 62
# parameter: limit — line 62
# parameter: path — line 62
# variable: descriptor — line 64
# variable: stream — line 71
# variable: before — line 72
# variable: raw — line 80
# variable: after — line 81
# definition: unique — line 92
# parameter: pairs — line 92
# variable: value — line 94
# variable: item — line 95
# variable: key — line 95
# definition: normalized — line 102
# parameter: components — line 102
# variable: rows — line 106
# variable: component — line 107
# variable: licenses — line 110
# variable: name — line 110
# variable: version — line 110
# variable: expression — line 129
# variable: row — line 137
# definition: observations — line 142
# variable: distribution — line 146
# variable: names — line 149
# variable: entry — line 151
# definition: collect — line 163
# parameter: license_root — line 163
# variable: raw — line 165
# variable: inventory — line 168
# variable: expected — line 169
# variable: row — line 175
# variable: module — line 177
# variable: sbom — line 177
# variable: actual — line 178
# variable: commits — line 183
# variable: blocks — line 186
# variable: digest — line 187
# variable: name — line 187
# variable: original — line 191
# END CODE MAP

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

INVENTORY_SHA256 = "9fbefc042a3212c768143a9a87117779718ae28dd4501c7b590534c0b988ad5c"
COMPILER = "48a229ceaefd4985c50990b14116b6d856af0985"


def bounded(path: Path, limit: int) -> bytes:
    """Read one bounded regular descriptor without blocking on a FIFO; reject changed observations and links."""
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(before.st_mode)
            or before.st_size > limit
        ):
            raise ValueError("notice input must be a bounded regular file")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > limit or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("notice input changed or exceeded its bound")
    return raw


def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate metadata fields before projecting a provider component inventory."""
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate notice metadata field")
        value[key] = item
    return value


def normalized(components: Any) -> list[tuple[str, str, str]]:
    """Bind the complete exact name/version/license inventory without provider build paths or platform hashes."""
    if not isinstance(components, list) or len(components) != 39:
        raise ValueError("review changed crypto component inventory")
    rows = []
    for component in components:
        if not isinstance(component, dict):
            raise ValueError("invalid crypto component")
        name, version, licenses = (
            component.get("name"),
            component.get("version"),
            component.get("licenses"),
        )
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9_-]{1,64}", name) is None
            or not isinstance(version, str)
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None
        ):
            raise ValueError("invalid crypto component identity")
        if (
            not isinstance(licenses, list)
            or len(licenses) != 1
            or not isinstance(licenses[0], dict)
            or set(licenses[0]) != {"expression"}
        ):
            raise ValueError("review changed crypto license declaration")
        expression = licenses[0]["expression"]
        if (
            not isinstance(expression, str)
            or not 1 <= len(expression) <= 200
            or not expression.isascii()
        ):
            raise ValueError("invalid crypto license expression")
        rows.append((name, version, expression))
    if len({row[:2] for row in rows}) != 39:
        raise ValueError("duplicate crypto component identity")
    return sorted(rows)


def observations() -> tuple[bytes, bytes]:
    """Inspect only the actually installed hash-locked cryptography wheel's SBOM and binding module."""
    from cryptography.hazmat.bindings import _rust

    distribution = importlib.metadata.distribution("cryptography")
    if distribution.version != "50.0.2":
        raise ValueError("review changed cryptography wheel version")
    names = [
        entry
        for entry in distribution.files or []
        if str(entry)
        .replace("\\", "/")
        .endswith("/sboms/cryptography-rust.cyclonedx.json")
    ]
    if len(names) != 1:
        raise ValueError("review missing or ambiguous crypto provider SBOM")
    return bounded(Path(distribution.locate_file(names[0])), 2 * 1024 * 1024), bounded(
        Path(_rust.__file__), 32 * 1024 * 1024
    )


def collect(license_root: Path) -> tuple[bytes, dict[str, Any]]:
    """Return exact original terms only after this OS's actual wheel inventory/compiler observation matches reviewed scope."""
    raw = bounded(license_root / "cryptography-50.0.2-rust-inventory.json", 65536)
    if hashlib.sha256(raw).hexdigest() != INVENTORY_SHA256:
        raise ValueError("captured crypto notice inventory identity changed")
    inventory = json.loads(raw, object_pairs_hook=unique)
    expected = inventory["internalComponents"] + [
        {
            "name": row["name"],
            "version": row["version"],
            "licenses": row["declaredLicenses"],
        }
        for row in inventory["externalComponents"]
    ]
    sbom, module = observations()
    actual = normalized(json.loads(sbom, object_pairs_hook=unique)["components"])
    if actual != normalized(expected):
        raise ValueError(
            "actual crypto wheel component/license inventory requires review"
        )
    commits = set(re.findall(rb"[/\\]rustc[/\\]([0-9a-f]{40})", module))
    if commits != {COMPILER.encode()}:
        raise ValueError("actual crypto Rust compiler identity requires review")
    blocks = []
    for name, digest in (
        ("cryptography-50.0.2-rust-notices.txt", inventory["combinedNoticesSha256"]),
        ("RUST-COPYRIGHT-library.html", inventory["rustLibraryNoticeSha256"]),
    ):
        original = bounded(license_root / name, 4 * 1024 * 1024)
        if hashlib.sha256(original).hexdigest() != digest:
            raise ValueError("original crypto/Rust notice text identity changed")
        blocks.append(b"\n\n" + name.encode() + b"\n" + original)
    return b"".join(blocks), {
        "schema": 1,
        "cryptography": "50.0.2",
        "actualModuleSha256": hashlib.sha256(module).hexdigest(),
        "actualProviderSbomSha256": hashlib.sha256(sbom).hexdigest(),
        "normalized39ComponentsSha256": hashlib.sha256(
            json.dumps(actual, separators=(",", ":")).encode()
        ).hexdigest(),
        "rustCompilerSourceCommit": COMPILER,
        "rustCompilerVersion": "1.98.1",
        "externalCrates": 32,
        "originalNoticeFiles": 62,
        "scope": "Actual per-OS wheel observations; conservative all-target provider inventory, not a dynamic linkage or legal-certification claim. Windows module hash is not used as an allowlist for other operating systems.",
    }
