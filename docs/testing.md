# Testing strategy and acceptance criteria

Created by Jason Stys. Threat-driven layers; no claim of exhaustive correctness.

## Test layers

| Layer | Evidence |
| --- | --- |
| Contract/unit | Wrong schema/types, duplicate JSON, trusted clock/floor, portable/reserved/private names, ancestor/case collisions and byte digests. |
| Crypto/format integration | Real Ed25519, wrong independent key, recomputed ZIP CRC with altered bytes, missing/extra members, compressed/symlink/oversize entries, prefix/suffix/comment rejection and repeatability. |
| State integration | Two activations, explicit rollback, preserved sequence, CAS/lock contention, interrupted commit residue, altered retained bytes, unknown targets and bounded history. |
| CLI | Actual lifecycle including keygen, no-overwrite, defaults, failures and standalone module entry point. |
| Independent inventory | Upstream pinned Draft7 schema plus exact wheel checksum/file relationships and deterministic namespace. |
| Property-based | 100 examples each of bounded random JSON, portable paths and arbitrary ZIP bytes, with controlled failures. |
| Cross-platform | Linux 3.12 and 3.14, Windows 3.14, macOS Intel 3.14; real symlink tests on POSIX, privilege-independent simulated junction checks on Windows. |
| Offline end-to-end | Prepare platform wheels online, only-loopback namespace, no IPv4/IPv6 main routes, blocked reserved-address connect, pip --no-index/--require-hashes, pip check, fresh interpreter re-verification and synthetic app health. |
| Security/quality | Strict mypy, ruff, code maps/file guide/privacy/schema fingerprint, pip-audit graph, pinned scanner hashes, Gitleaks, actionlint, ShellCheck, security-extended CodeQL. |

Coverage gate is >=95% combined statements/branches over all runtime modules, with no exclusion pragmas. 100% coverage (when measured) does not mean all boolean combinations, race interleavings or attacks were tested. Runner kernels/filesystems differ. Windows real symlink privilege is not assumed.

## Commands

```text
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m pytest --cov=drkit --cov-report=term-missing:skip-covered
python scripts/code_map.py --check
python scripts/file_guide.py --check
python scripts/validate_repo.py
python -m pip_audit -r requirements-dev.lock --disable-pip --no-deps
```

Test output stays in logs/ignored local folders; no Actions upload/cache steps. Latest status and immutable accepted-source reports are separate.
