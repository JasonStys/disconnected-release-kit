"""Jason Stys: deterministic Ed25519-signed ZIP bundles with independent trust and bounded verification."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: DOMAIN — line 125
# definition: Verified — line 129
# variable: metadata — line 132
# variable: files — line 133
# variable: digest — line 134
# variable: archive — line 135
# definition: pack — line 138
# parameter: files — line 138
# variable: buffer — line 140
# variable: archive — line 143
# variable: data — line 144
# variable: name — line 144
# variable: info — line 145
# attribute: create_system — line 146
# attribute: external_attr — line 147
# definition: build — line 152
# parameter: files — line 153
# parameter: key — line 154
# parameter: product — line 156
# parameter: version — line 157
# parameter: sequence — line 158
# parameter: target — line 159
# parameter: created — line 160
# parameter: expires — line 161
# parameter: revision — line 162
# variable: meta — line 165
# variable: total — line 168
# variable: data — line 169
# variable: name — line 169
# variable: total — line 175
# variable: contents — line 177
# variable: data — line 181
# variable: name — line 181
# variable: raw — line 183
# variable: signed — line 185
# variable: result — line 186
# definition: verify — line 191
# parameter: data — line 191
# parameter: policy — line 191
# parameter: trusted_key — line 191
# variable: _ — line 202
# variable: disk — line 203
# variable: start_disk — line 204
# variable: count_disk — line 205
# variable: count — line 206
# variable: directory_size — line 207
# variable: directory_offset — line 208
# variable: comment — line 209
# variable: contents — line 221
# variable: archive — line 223
# variable: members — line 224
# variable: total — line 226
# variable: member — line 227
# variable: name — line 228
# variable: cap — line 248
# variable: total — line 250
# variable: raw — line 265
# variable: signature — line 265
# variable: meta — line 271
# variable: entry — line 273
# variable: entry — line 276
# variable: blob — line 277
# variable: payload — line 282
# variable: blob — line 283
# variable: name — line 283
# definition: read_file — line 297
# parameter: limit — line 297
# parameter: path — line 297
# variable: before — line 301
# variable: flags — line 310
# variable: descriptor — line 311
# variable: opened — line 313
# variable: stream — line 320
# variable: value — line 321
# definition: collect — line 328
# parameter: root — line 328
# variable: files — line 334
# variable: total — line 335
# variable: visited — line 336
# variable: pending — line 337
# variable: directory — line 339
# variable: path — line 340
# variable: visited — line 341
# variable: relative — line 347
# variable: name — line 349
# variable: total — line 352
# END CODE MAP

from __future__ import annotations

import io
import os
import stat
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from drkit.contracts import (
    MAX_BUNDLE,
    MAX_ENTRIES,
    MAX_FILE,
    MAX_MANIFEST,
    Policy,
    Rejected,
    canonical,
    header,
    integer,
    manifest,
    payload_path,
    require,
    sha,
)
from drkit.inventory import inventory

DOMAIN = b"disconnected-release-kit/v1\0"


@dataclass(frozen=True)
class Verified:
    """Authenticated bytes and manifest snapshot; never execute carried files automatically."""

    metadata: dict[str, Any]
    files: dict[str, bytes]
    digest: str
    archive: bytes


def pack(files: dict[str, bytes]) -> bytes:
    """Encode one canonical ZIP_STORED profile with sorted names, fixed time and regular-file modes."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(
        buffer, "w", compression=zipfile.ZIP_STORED, allowZip64=False
    ) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def build(
    files: dict[str, bytes],
    key: bytes,
    *,
    product: str,
    version: str,
    sequence: int,
    target: str,
    created: int,
    expires: int,
    revision: str,
) -> bytes:
    """Sign an explicit reviewed bounded file mapping; a secret-scanning process is still required."""
    meta = header(product, version, sequence, target, created, expires, revision)
    require(len(key) == 32, "invalid signing key length")
    require(1 <= len(files) <= MAX_ENTRIES - 3, "invalid payload count")
    total = 0
    for name, data in files.items():
        payload_path(name)
        require(
            isinstance(data, bytes) and len(data) <= MAX_FILE,
            "payload exceeds file cap",
        )
        total += len(data)
        require(total <= MAX_BUNDLE - MAX_FILE, "payload total exceeds size cap")
    contents = dict(files)
    contents["inventory.spdx.json"] = inventory(files, product, version, created)
    meta["files"] = [
        dict(path=name, size=len(data), sha256=sha(data))
        for name, data in sorted(contents.items())
    ]
    raw = canonical(meta)
    manifest(raw, Policy(product, target, created))
    signed = Ed25519PrivateKey.from_private_bytes(key).sign(DOMAIN + raw)
    result = pack({**contents, "manifest.json": raw, "manifest.sig": signed})
    require(len(result) <= MAX_BUNDLE, "bundle exceeds size cap")
    return result


def verify(data: bytes, trusted_key: bytes, policy: Policy) -> Verified:
    """Authenticate against only an external key, then verify every byte and canonical ZIP layout."""
    policy.validate()
    require(
        len(data) <= MAX_BUNDLE and len(trusted_key) == 32, "invalid bundle/key size"
    )
    # Bound central-directory allocation before ZipFile parses untrusted metadata.
    require(
        len(data) >= 22 and data[-22:-18] == b"PK\x05\x06", "noncanonical ZIP layout"
    )
    (
        _,
        disk,
        start_disk,
        count_disk,
        count,
        directory_size,
        directory_offset,
        comment,
    ) = struct.unpack("<4s4H2IH", data[-22:])
    require(
        disk == start_disk == comment == 0 and count_disk == count,
        "unsupported ZIP volume/comment",
    )
    require(4 <= count <= MAX_ENTRIES, "invalid ZIP entry count")
    require(
        directory_size <= MAX_MANIFEST
        and directory_offset + directory_size == len(data) - 22,
        "invalid ZIP directory bounds",
    )
    contents: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            require(4 <= len(members) <= MAX_ENTRIES, "invalid ZIP entry count")
            total = 0
            for member in members:
                name = member.filename
                require(
                    name not in contents
                    and (
                        name in {"manifest.json", "manifest.sig", "inventory.spdx.json"}
                        or name.startswith("payload/")
                    ),
                    "unexpected/duplicate ZIP entry",
                )
                require(
                    not member.is_dir()
                    and stat.S_IFMT(member.external_attr >> 16) == stat.S_IFREG,
                    "nonregular ZIP entry",
                )
                require(
                    member.compress_type == zipfile.ZIP_STORED
                    and member.compress_size == member.file_size
                    and not member.flag_bits & 1,
                    "compressed/encrypted ZIP entry",
                )
                cap = MAX_MANIFEST if name == "manifest.json" else MAX_FILE
                require(0 <= member.file_size <= cap, "ZIP entry exceeds cap")
                total += member.file_size
                require(total <= MAX_BUNDLE, "ZIP payload exceeds cap")
                contents[name] = archive.read(member)
    except (
        zipfile.BadZipFile,
        OSError,
        RuntimeError,
        NotImplementedError,
        UnicodeError,
    ) as error:
        raise Rejected("invalid ZIP data") from error
    require(
        "manifest.json" in contents and "manifest.sig" in contents,
        "missing signed metadata",
    )
    raw, signature = contents.pop("manifest.json"), contents.pop("manifest.sig")
    require(len(signature) == 64, "invalid signature length")
    try:
        Ed25519PublicKey.from_public_bytes(trusted_key).verify(signature, DOMAIN + raw)
    except InvalidSignature as error:
        raise Rejected("signature verification failed") from error
    meta = manifest(raw, policy)
    require(
        set(contents) == {entry["path"] for entry in meta["files"]},
        "manifest/ZIP file set mismatch",
    )
    for entry in meta["files"]:
        blob = contents[entry["path"]]
        require(
            len(blob) == entry["size"] and sha(blob) == entry["sha256"],
            "payload checksum/size mismatch",
        )
    payload = {
        name: blob for name, blob in contents.items() if name != "inventory.spdx.json"
    }
    require(
        contents["inventory.spdx.json"]
        == inventory(payload, meta["product"], meta["version"], meta["created"]),
        "inventory mismatch",
    )
    require(
        pack({**contents, "manifest.json": raw, "manifest.sig": signature}) == data,
        "noncanonical ZIP layout",
    )
    return Verified(meta, contents, sha(data), data)


def read_file(path: Path, limit: int = MAX_FILE) -> bytes:
    """Read a bounded same-descriptor regular file; reject a last-component replacement without blocking on FIFOs."""
    require(integer(limit, 0, MAX_BUNDLE), "invalid local read cap")
    try:
        before = path.lstat()
    except OSError:
        raise Rejected("regular local file required") from None
    require(
        stat.S_ISREG(before.st_mode)
        and not path.is_symlink()
        and not path.is_junction(),
        "regular local file required",
    )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require(
            stat.S_ISREG(opened.st_mode)
            and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
            "local input changed or is nonregular",
        )
        require(opened.st_size <= limit, "local file exceeds size cap")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            value = stream.read(limit + 1)
        require(len(value) <= limit, "local file exceeds size cap")
        return value
    finally:
        os.close(descriptor)


def collect(root: Path) -> dict[str, bytes]:
    """Collect only an explicit reviewed staging folder; reject links, excessive nesting and private names."""
    require(
        root.is_dir() and not root.is_symlink() and not root.is_junction(),
        "regular staging directory required",
    )
    files: dict[str, bytes] = {}
    total = 0
    visited = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            visited += 1
            require(visited <= MAX_ENTRIES * 2, "staging directory entry cap exceeded")
            require(
                not path.is_symlink() and not path.is_junction(),
                "staging links are forbidden",
            )
            relative = path.relative_to(root).as_posix()
            if path.is_file():
                name = payload_path("payload/" + relative)
                require(len(files) < MAX_ENTRIES - 3, "staging file count exceeds cap")
                files[name] = read_file(path)
                total += len(files[name])
                require(
                    total <= MAX_BUNDLE - MAX_FILE, "staging total exceeds size cap"
                )
            else:
                require(path.is_dir(), "nonregular staging entry")
                payload_path("payload/" + relative + "/entry")
                pending.append(path)
    return files
