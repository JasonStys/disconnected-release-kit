"""Jason Stys: strict release contracts, bounded canonical JSON and portable payload paths."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: MAX_FILE — line 78
# variable: MAX_BUNDLE — line 79
# variable: MAX_ENTRIES — line 80
# variable: MAX_MANIFEST — line 81
# variable: MAX_LIFETIME — line 82
# variable: ID — line 83
# variable: DIGEST — line 84
# variable: REVISION — line 85
# variable: VERSION — line 86
# variable: RESERVED — line 87
# variable: i — line 92
# variable: i — line 93
# definition: Rejected — line 97
# definition: require — line 101
# parameter: condition — line 101
# parameter: message — line 101
# definition: sha — line 107
# parameter: data — line 107
# definition: canonical — line 112
# parameter: value — line 112
# definition: pairs — line 119
# parameter: items — line 119
# variable: result — line 121
# variable: key — line 122
# variable: value — line 122
# definition: decode — line 128
# parameter: data — line 128
# parameter: limit — line 128
# definition: integer — line 137
# parameter: high — line 137
# parameter: low — line 137
# parameter: value — line 137
# definition: payload_path — line 142
# parameter: name — line 142
# variable: parts — line 145
# variable: part — line 147
# definition: Policy — line 165
# variable: product — line 168
# variable: target — line 169
# variable: now — line 170
# variable: minimum_sequence — line 171
# definition: validate — line 173
# parameter: self — line 173
# definition: header — line 186
# parameter: product — line 187
# parameter: version — line 188
# parameter: sequence — line 189
# parameter: target — line 190
# parameter: created — line 191
# parameter: expires — line 192
# parameter: revision — line 193
# definition: manifest — line 223
# parameter: data — line 223
# parameter: policy — line 223
# variable: value — line 226
# variable: name — line 247
# variable: entries — line 269
# variable: names — line 274
# variable: total — line 275
# variable: entry — line 276
# variable: name — line 281
# variable: total — line 292
# parameter: entry — line 298
# variable: name — line 303
# variable: index — line 304
# END CODE MAP

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, cast

MAX_FILE = 16 * 1024 * 1024
MAX_BUNDLE = 64 * 1024 * 1024
MAX_ENTRIES = 256
MAX_MANIFEST = 128 * 1024
MAX_LIFETIME = 7 * 86400
ID = re.compile(r"[a-z][a-z0-9-]{0,47}")
DIGEST = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})")
RESERVED = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


class Rejected(ValueError):
    """Public fixed-message admission failure; never include submitted secrets in the message."""


def require(condition: bool, message: str) -> None:
    """Raise a fixed application error unless a contract condition is true."""
    if not condition:
        raise Rejected(message)


def sha(data: bytes) -> str:
    """Return the SHA256 digest of bounded supplied bytes."""
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    """Encode this application profile: sorted UTF-8 JSON, integers only by contract, no NaN."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate object keys before any dictionary can hide them."""
    result: dict[str, Any] = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(data: bytes, limit: int = MAX_MANIFEST) -> Any:
    """Decode bounded JSON and normalize parser/resource failures to admission errors."""
    require(len(data) <= limit, "JSON exceeds size cap")
    try:
        return json.loads(data, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise Rejected("invalid JSON") from error


def integer(value: Any, low: int, high: int) -> bool:
    """Validate exact integers, excluding booleans and floats."""
    return type(value) is int and low <= value <= high


def payload_path(name: Any) -> str:
    """Allow shallow ASCII regular-file paths, excluding traversal and Windows/private names."""
    require(isinstance(name, str) and len(name) <= 240, "invalid payload path")
    parts = name.split("/")
    require(2 <= len(parts) <= 5 and parts[0] == "payload", "invalid payload path")
    for part in parts:
        require(
            bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", part)),
            "invalid payload component",
        )
        require(
            not part.endswith(".") and part.lower().split(".")[0] not in RESERVED,
            "reserved payload component",
        )
        require(
            not part.lower().endswith((".key", ".pem", ".env"))
            and part != "__pycache__",
            "private payload component",
        )
    return cast(str, name)


@dataclass(frozen=True)
class Policy:
    """Independent operator product/target/clock/floor; the bundle cannot choose its own policy."""

    product: str
    target: str
    now: int
    minimum_sequence: int = 0

    def validate(self) -> None:
        """Validate caller policy before using it to admit any release."""
        require(
            bool(ID.fullmatch(self.product)) and bool(ID.fullmatch(self.target)),
            "invalid trusted policy",
        )
        require(
            integer(self.now, 0, 4_102_444_800)
            and integer(self.minimum_sequence, 0, 2**31 - 1),
            "invalid trusted clock/floor",
        )


def header(
    product: Any,
    version: Any,
    sequence: Any,
    target: Any,
    created: Any,
    expires: Any,
    revision: Any,
) -> dict[str, Any]:
    """Validate bounded release identity/time/provenance labels; caller labels are not attestations."""
    require(isinstance(product, str) and bool(ID.fullmatch(product)), "invalid product")
    require(isinstance(target, str) and bool(ID.fullmatch(target)), "invalid target")
    require(
        isinstance(version, str) and bool(VERSION.fullmatch(version)), "invalid version"
    )
    require(integer(sequence, 1, 2**31 - 1), "invalid sequence")
    require(
        integer(created, 0, 4_102_444_800) and integer(expires, 0, 4_102_444_800),
        "invalid release time",
    )
    require(0 < expires - created <= MAX_LIFETIME, "invalid release lifetime")
    require(
        isinstance(revision, str) and bool(REVISION.fullmatch(revision)),
        "invalid source revision",
    )
    return dict(
        schema=1,
        product=product,
        version=version,
        sequence=sequence,
        target=target,
        created=created,
        expires=expires,
        source_revision=revision,
    )


def manifest(data: bytes, policy: Policy) -> dict[str, Any]:
    """Validate exact authenticated manifest shape, file set, expiry and independent target/floor."""
    policy.validate()
    value = decode(data)
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema",
            "product",
            "version",
            "sequence",
            "target",
            "created",
            "expires",
            "source_revision",
            "files",
        },
        "invalid manifest fields",
    )
    require(type(value["schema"]) is int and value["schema"] == 1, "unsupported schema")
    header(
        *(
            value[name]
            for name in (
                "product",
                "version",
                "sequence",
                "target",
                "created",
                "expires",
                "source_revision",
            )
        )
    )
    require(
        value["product"] == policy.product and value["target"] == policy.target,
        "product/target mismatch",
    )
    require(
        value["created"] <= policy.now < value["expires"], "release not currently valid"
    )
    require(
        value["sequence"] >= policy.minimum_sequence,
        "release below trusted sequence floor",
    )
    entries = value["files"]
    require(
        isinstance(entries, list) and 2 <= len(entries) <= MAX_ENTRIES - 2,
        "invalid manifest file count",
    )
    names: set[str] = set()
    total = 0
    for entry in entries:
        require(
            isinstance(entry, dict) and set(entry) == {"path", "size", "sha256"},
            "invalid file descriptor",
        )
        name = entry["path"]
        if name != "inventory.spdx.json":
            payload_path(name)
        require(name.casefold() not in names, "colliding payload paths")
        names.add(name.casefold())
        require(
            integer(entry["size"], 0, MAX_FILE)
            and isinstance(entry["sha256"], str)
            and bool(DIGEST.fullmatch(entry["sha256"])),
            "invalid file size/digest",
        )
        total += entry["size"]
    require(
        "inventory.spdx.json" in names and total <= MAX_BUNDLE,
        "invalid inventory/total size",
    )
    require(
        entries == sorted(entries, key=lambda entry: entry["path"]), "unsorted manifest"
    )
    require(
        not any(
            "/".join(name.split("/")[:index]) in names
            for name in names
            for index in range(1, len(name.split("/")))
        ),
        "file/directory collision",
    )
    require(canonical(value) == data, "noncanonical manifest")
    return cast(dict[str, Any], value)
