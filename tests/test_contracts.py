"""Jason Stys: exact schema, time, path, canonical JSON and property-based admission boundaries."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# parameter: x — line 73
# definition: test_paths_reject — line 75
# parameter: path — line 75
# definition: test_contract_primitives — line 81
# definition: test_json_reject — line 97
# parameter: data — line 97
# definition: test_header_reject — line 117
# parameter: field — line 117
# parameter: value — line 117
# variable: values — line 119
# definition: test_policy_reject — line 142
# parameter: value — line 142
# definition: test_json_fuzz — line 150
# parameter: data — line 150
# definition: test_path_fuzz — line 160
# parameter: value — line 160
# variable: admitted — line 163
# definition: test_manifest_shapes — line 173
# parameter: archive — line 173
# parameter: policy — line 173
# variable: container — line 178
# variable: valid — line 179
# variable: variations — line 180
# variable: value — line 191
# variable: altered — line 194
# END CODE MAP

import json

import pytest
from conftest import NOW
from hypothesis import given, settings
from hypothesis import strategies as st

from drkit.contracts import (
    MAX_MANIFEST,
    Policy,
    Rejected,
    canonical,
    decode,
    header,
    integer,
    manifest,
    payload_path,
    sha,
)


@pytest.mark.parametrize(
    "path",
    [
        "../app.py",
        "/payload/app",
        "payload/../app",
        "payload/a\\b",
        "payload/a:stream",
        "payload/NUL.txt",
        "payload/com1",
        "payload/a.",
        "payload/.env",
        "payload/a.key",
        "payload/a.pem",
        "payload/a.env",
        "payload/__pycache__/a",
        "payload/" + "x" * 129,
        "payload/a/b/c/d/e",
        "payload/é",
        "",
        None,
    ],
    ids=lambda x: str(x)[:45],
)
def test_paths_reject(path: object) -> None:
    """Reject portable-name bypasses and traversal before any filesystem writes."""
    with pytest.raises(Rejected):
        payload_path(path)


def test_contract_primitives() -> None:
    """Exercise exact numeric/profile boundaries and safe digest calculation."""
    assert integer(0, 0, 1) and not integer(True, 0, 1) and not integer(1.0, 0, 1)
    assert payload_path("payload/Service-1_data.py") == "payload/Service-1_data.py"
    assert (
        sha(b"abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert decode(canonical({"z": 1, "a": []})) == {"a": [], "z": 1}


@pytest.mark.parametrize(
    "data",
    [b'{"x":1,"x":2}', b"{", b"\xff", b"[" * 2000, b"x" * (MAX_MANIFEST + 1)],
    ids=["duplicate", "syntax", "encoding", "depth", "size"],
)
def test_json_reject(data: bytes) -> None:
    """Bound duplicate-key, syntax, encoding, recursion and excessive-size JSON."""
    with pytest.raises(Rejected):
        decode(data)


@pytest.mark.parametrize(
    "field,value",
    [
        ("product", "INVALID"),
        ("target", []),
        ("version", "1.01.0"),
        ("sequence", True),
        ("sequence", 0),
        ("created", -1),
        ("expires", NOW - 1),
        ("expires", NOW + 8 * 86400),
        ("revision", "fake"),
    ],
)
def test_header_reject(field: str, value: object) -> None:
    """Reject wrong types, lifetime and caller-provenance labels without string coercion."""
    values = dict(
        product="demo-service",
        version="1.0.0",
        sequence=1,
        target="portable-source",
        created=NOW - 1,
        expires=NOW + 3600,
        revision="a" * 40,
    )
    values[field] = value
    with pytest.raises(Rejected):
        header(**values)


@pytest.mark.parametrize(
    "value",
    [
        Policy("Invalid", "portable", NOW),
        Policy("demo", "Invalid", NOW),
        Policy("demo", "portable", -1),
        Policy("demo", "portable", NOW, True),
    ],
)
def test_policy_reject(value: Policy) -> None:
    """Validate trusted-side clock/target inputs even for otherwise valid bundles."""
    with pytest.raises(Rejected):
        value.validate()


@given(st.binary(max_size=2048))
@settings(max_examples=100, deadline=None)
def test_json_fuzz(data: bytes) -> None:
    """Arbitrary bounded bytes yield a parsed value or a controlled rejection, not execution."""
    try:
        decode(data)
    except Rejected:
        pass


@given(st.text(max_size=170))
@settings(max_examples=100, deadline=None)
def test_path_fuzz(value: str) -> None:
    """Every admitted portable path remains inside the payload namespace."""
    try:
        admitted = payload_path(value)
    except Rejected:
        return
    assert (
        admitted.startswith("payload/")
        and ".." not in admitted.split("/")
        and "\\" not in admitted
    )


def test_manifest_shapes(archive: bytes, policy: Policy) -> None:
    """Validate malformed signed-body structures separately from cryptographic integrity."""
    import io
    import zipfile

    with zipfile.ZipFile(io.BytesIO(archive)) as container:
        valid = json.loads(container.read("manifest.json"))
    variations = [
        [],
        {},
        {**valid, "schema": True},
        {**valid, "extra": 1},
        {**valid, "files": []},
        {**valid, "files": [{}]},
        {**valid, "files": valid["files"] + [{}]},
        {**valid, "files": list(reversed(valid["files"]))},
        {**valid, "files": [*valid["files"], valid["files"][1]]},
    ]
    for value in variations:
        with pytest.raises(Rejected):
            manifest(canonical(value), policy)
    altered = json.loads(json.dumps(valid))
    altered["files"][1]["size"] = False
    with pytest.raises(Rejected):
        manifest(canonical(altered), policy)
    altered["files"][1]["size"] = 1
    altered["files"][1]["sha256"] = "bad"
    with pytest.raises(Rejected):
        manifest(canonical(altered), policy)
    with pytest.raises(Rejected):
        manifest(json.dumps(valid, indent=2).encode(), policy)
