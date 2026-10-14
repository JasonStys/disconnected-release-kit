"""Jason Stys: synthetic reproducibility, admission rejection and explicit rollback acceptance report."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 50
# variable: NOW — line 51
# definition: run — line 54
# parameter: output — line 54
# variable: private — line 57
# variable: trusted — line 58
# variable: source — line 61
# variable: payload — line 62
# variable: settings — line 63
# variable: first — line 72
# variable: repeated — line 73
# variable: second — line 74
# variable: policy — line 75
# variable: admitted — line 76
# variable: archive — line 77
# variable: entry — line 78
# variable: files — line 78
# variable: cases — line 79
# variable: candidate — line 80
# variable: check — line 80
# variable: key — line 80
# variable: name — line 80
# variable: deployment — line 117
# variable: one — line 119
# variable: two — line 120
# variable: restored — line 121
# variable: report — line 128
# definition: main — line 149
# variable: parser — line 151
# variable: args — line 153
# END CODE MAP

from __future__ import annotations

import argparse
import io
import json
import platform
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drkit.bundle import build, pack, verify
from drkit.contracts import Policy, Rejected, sha
from drkit.deploy import activate, initialize, rollback

ROOT = Path(__file__).resolve().parents[1]
NOW = 1_700_000_001


def run(output: Path) -> dict[str, object]:
    """Run actual cryptography/deployment on synthetic bytes; keys/bundles stay in ignored output."""
    output.mkdir(parents=True)
    private = Ed25519PrivateKey.generate().private_bytes_raw()
    trusted = (
        Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes_raw()
    )
    source = (ROOT / "examples/service.py").read_bytes()
    payload = {"payload/service.py": source}
    settings = dict(
        product="demo-service",
        version="1.0.1",
        sequence=1,
        target="portable-source",
        created=NOW - 1,
        expires=NOW + 3600,
        revision="a" * 40,
    )
    first = build(payload, private, **settings)
    repeated = build(payload, private, **settings)
    second = build(payload, private, **{**settings, "version": "1.0.2", "sequence": 2})
    policy = Policy("demo-service", "portable-source", NOW)
    admitted = verify(first, trusted, policy)
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        files = {entry.filename: archive.read(entry) for entry in archive.infolist()}
    cases = {}
    for name, candidate, key, check in [
        (
            "checksum-tamper",
            pack({**files, "payload/service.py": source + b"#tamper"}),
            trusted,
            policy,
        ),
        (
            "wrong-trust",
            first,
            Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
            policy,
        ),
        ("extra-member", pack({**files, "payload/extra": b"x"}), trusted, policy),
        (
            "expired",
            first,
            trusted,
            Policy("demo-service", "portable-source", NOW + 3600),
        ),
        ("future", first, trusted, Policy("demo-service", "portable-source", NOW - 2)),
        ("wrong-product", first, trusted, Policy("other", "portable-source", NOW)),
        ("wrong-platform", first, trusted, Policy("demo-service", "other", NOW)),
        (
            "sequence-floor",
            first,
            trusted,
            Policy("demo-service", "portable-source", NOW, 2),
        ),
        ("trailing-data", first + b"x", trusted, policy),
    ]:
        try:
            verify(candidate, key, check)
        except Rejected:
            cases[name] = "rejected"
        else:
            raise AssertionError("negative admission unexpectedly passed")
    deployment = output / "deployment"
    initialize(deployment)
    one = activate(deployment, first, trusted, policy, None)
    two = activate(deployment, second, trusted, policy, one["current"])
    restored = rollback(deployment, one["current"], two["current"], trusted, policy)
    try:
        activate(deployment, first, trusted, policy, restored["current"])
    except Rejected:
        cases["normal-downgrade-after-rollback"] = "rejected"
    else:
        raise AssertionError("downgrade admitted")
    report = dict(
        author="Jason Stys",
        scope="synthetic frozen-clock delivery regression",
        python=platform.python_version(),
        reproducible=first == repeated,
        authenticated_files=len(admitted.files),
        archive_bytes=len(first),
        bundle_sha256=sha(first),
        negative_cases=cases,
        versions_activated=2,
        explicit_rollback=True,
        highest_sequence=restored["highest_sequence"],
        retained_releases=2,
    )
    assert report["reproducible"] is True
    (output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    return report


def main() -> None:
    """Emit safe synthetic evidence without publishing ephemeral keys or release archives."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "out/demo")
    args = parser.parse_args()
    print(json.dumps(run(args.out), sort_keys=True))


if __name__ == "__main__":
    main()
