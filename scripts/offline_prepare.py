"""Jason Stys: package reviewed source plus hash-locked platform wheels for an explicit disposable CI test."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 27
# definition: main — line 30
# variable: output — line 32
# variable: staging — line 34
# variable: source — line 38
# variable: source — line 40
# variable: revision — line 46
# variable: target — line 49
# variable: private — line 50
# variable: created — line 51
# variable: archive — line 52
# END CODE MAP

import json
import platform
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drkit.bundle import build, collect

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Prepare a signed snapshot and separate demo public trust; never commit key or wheel payloads."""
    output = ROOT / "out/offline"
    output.mkdir(parents=True)
    staging = output / "source"
    staging.mkdir()
    (staging / "drkit").mkdir()
    (staging / "wheels").mkdir()
    for source in sorted((ROOT / "drkit").glob("*.py")):
        (staging / "drkit" / source.name).write_bytes(source.read_bytes())
    for source in sorted((ROOT / "out/wheels").glob("*.whl")):
        (staging / "wheels" / source.name).write_bytes(source.read_bytes())
    (staging / "requirements.lock").write_bytes(
        (ROOT / "requirements.lock").read_bytes()
    )
    (staging / "service.py").write_bytes((ROOT / "examples/service.py").read_bytes())
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    target = f"{sys.platform}-{platform.machine().lower().replace('_', '-')}-py{sys.version_info.major}{sys.version_info.minor}"
    private = Ed25519PrivateKey.generate()
    created = int(time.time())
    archive = build(
        collect(staging),
        private.private_bytes_raw(),
        product="demo-service",
        version="1.0.0",
        sequence=1,
        target=target,
        created=created,
        expires=created + 86400,
        revision=revision,
    )
    (output / "bundle.zip").write_bytes(archive)
    (output / "trust.pub").write_bytes(private.public_key().public_bytes_raw())
    (output / "settings.json").write_text(
        json.dumps(dict(target=target, source_revision=revision)), encoding="utf-8"
    )
    print(
        json.dumps(
            dict(
                author="Jason Stys",
                scope="platform-specific hash-locked preparation",
                wheel_count=len(list((staging / "wheels").glob("*.whl"))),
                archive_bytes=len(archive),
                target=target,
            )
        )
    )


if __name__ == "__main__":
    main()
