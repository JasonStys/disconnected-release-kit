"""Jason Stys: isolated synthetic signing fixtures; no personal data or production trust."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: NOW — line 28
# definition: secret — line 32
# definition: trusted — line 38
# parameter: secret — line 38
# definition: policy — line 44
# definition: release — line 49
# parameter: changes — line 49
# parameter: secret — line 49
# parameter: sequence — line 49
# variable: settings — line 51
# definition: archive — line 65
# parameter: secret — line 65
# definition: root — line 71
# parameter: tmp_path — line 71
# END CODE MAP

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drkit.bundle import build
from drkit.contracts import Policy

NOW = 1_700_000_001


@pytest.fixture
def secret() -> bytes:
    """Generate a fresh test-only signing key, never a committed production credential."""
    return Ed25519PrivateKey.generate().private_bytes_raw()


@pytest.fixture
def trusted(secret: bytes) -> bytes:
    """Derive separately passed public test trust for verifier inputs."""
    return Ed25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()


@pytest.fixture
def policy() -> Policy:
    """Provide an explicit synthetic frozen clock and independent product/target."""
    return Policy("demo-service", "portable-source", NOW)


def release(secret: bytes, sequence: int = 1, **changes: Any) -> bytes:
    """Build one synthetic release with caller changes used for independent negative tests."""
    settings = dict(
        product="demo-service",
        version=f"1.0.{sequence}",
        sequence=sequence,
        target="portable-source",
        created=NOW - 1,
        expires=NOW + 3600,
        revision="a" * 40,
    )
    settings.update(changes)
    return build({"payload/app.py": b'print("synthetic")\n'}, secret, **settings)


@pytest.fixture
def archive(secret: bytes) -> bytes:
    """Supply a valid small signed release for mutations."""
    return release(secret)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """Reserve an uncreated temporary deployment path."""
    return tmp_path / "deployment"
