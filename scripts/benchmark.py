"""Jason Stys: bounded synthetic build/verify benchmark; no hardware-independent speed promises."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: main — line 34
# variable: private — line 36
# variable: key — line 37
# variable: trusted — line 37
# variable: files — line 38
# variable: policy — line 39
# variable: settings — line 40
# variable: sample — line 49
# variable: build_ms — line 51
# variable: verify_ms — line 51
# variable: _ — line 53
# variable: start — line 54
# variable: sample — line 55
# variable: midpoint — line 56
# variable: end — line 58
# variable: _ — line 61
# variable: peak — line 61
# END CODE MAP

import json
import platform
import statistics
import time
import tracemalloc

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drkit.bundle import build, verify
from drkit.contracts import Policy


def main() -> None:
    """Measure repeated release creation/admission plus Python allocations for a fixed 1 MiB payload."""
    private = Ed25519PrivateKey.generate()
    key, trusted = private.private_bytes_raw(), private.public_key().public_bytes_raw()
    files = {"payload/data.bin": b"synthetic-012345" * 65536}
    policy = Policy("demo-service", "portable-source", 1_700_000_001)
    settings = dict(
        product=policy.product,
        target=policy.target,
        version="1.0.0",
        sequence=1,
        created=policy.now - 1,
        expires=policy.now + 60,
        revision="a" * 40,
    )
    sample = build(files, key, **settings)
    verify(sample, trusted, policy)
    build_ms, verify_ms = [], []
    tracemalloc.start()
    for _ in range(15):
        start = time.perf_counter_ns()
        sample = build(files, key, **settings)
        midpoint = time.perf_counter_ns()
        verify(sample, trusted, policy)
        end = time.perf_counter_ns()
        build_ms.append((midpoint - start) / 1e6)
        verify_ms.append((end - midpoint) / 1e6)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(
        json.dumps(
            dict(
                author="Jason Stys",
                scope="synthetic signed 1 MiB payload",
                python=platform.python_version(),
                samples=15,
                payload_bytes=sum(map(len, files.values())),
                archive_bytes=len(sample),
                build_median_ms=statistics.median(build_ms),
                verify_median_ms=statistics.median(verify_ms),
                python_peak_bytes=peak,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
