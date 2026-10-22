# Disconnected Release Kit

[![Validate](https://github.com/JasonStys/disconnected-release-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/JasonStys/disconnected-release-kit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/JasonStys/disconnected-release-kit/actions/workflows/codeql.yml/badge.svg)](https://github.com/JasonStys/disconnected-release-kit/actions/workflows/codeql.yml)

Created by **Jason Stys** — [GitHub/contact](https://github.com/JasonStys) · [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/).

A Python/Bash portfolio lab for delivering reviewed software into disconnected environments: deterministic signed bundles, independent public-key trust, exact file/SBOM verification, staged activation, explicit rollback, and a real hash-locked offline wheelhouse installation test.

This is a delivery toolkit, not a cloud service, universal installer, antivirus, TUF implementation, or government compliance certification. It never automatically executes submitted payloads. Only the CI's explicitly authored synthetic example is installed/run.

## Features

| Feature | Behavior |
| --- | --- |
| Reproducible packaging | Fixed sorted ZIP_STORED profile; same reviewed bytes, metadata and key give identical bundle bytes. |
| Independent authenticity | Maintained cryptography Ed25519 signs domain-separated canonical manifest bytes. Trust is a separately supplied 32-byte public key, never embedded bundle trust. |
| Bounded admission | Enforce exact entries, size/hash descriptors, canonical layout, portable paths, expiry, product, target and trusted sequence floor. Reject symlinks, duplicates and compressed members. |
| Machine-readable inventory | Signed SPDX 2.3 exact file/wheel-blob inventory, independently checked against a pinned upstream schema. Unknown licenses stay NOASSERTION. |
| Safe activation | New owned root, exclusive operation lock, digest-named releases, full installed-byte validation, atomic state pointer and expected-current comparison. |
| Explicit rollback | Select a retained digest deliberately; revalidate trust/content/expiry, keep the highest sequence and retain all releases. |
| Actual offline evidence | Disposable Linux namespace with only loopback and no main routes; install wheels with --no-index/--require-hashes and reverify from a fresh environment. |
| Cross-platform assurance | Windows, macOS and Linux; Python 3.12/3.14, property-based tests, coverage, strict typing, dependency/secret/workflow scans and CodeQL. |

## Quick start

Requires Python 3.12+ and an initial trusted online setup. This does **not** bootstrap trust from an unverified bundle.

```text
python -m venv .venv
# Windows: .venv/Scripts/python; Linux/macOS: .venv/bin/python
.venv/Scripts/python -m pip install --require-hashes -r requirements-dev.lock
.venv/Scripts/python -m pytest --cov=drkit
.venv/Scripts/python -m drkit.cli --help
```

With the environment active (or PYTHONPATH set to the repo root):

```text
python scripts/demo.py --out out/demo-first
python scripts/benchmark.py
```

The synthetic demo uses a clearly labeled **frozen test clock**, creates two signed versions, rejects tampering, activates both and rolls back while retaining its sequence floor. Outputs remain under ignored `out/`. See [usage](docs/usage.md) for operational CLI commands and actual disconnected preparation; never use `--now` to bypass expiry in operational use.

## Documentation

[Architecture/ADR](docs/architecture.md) · [Contracts](docs/contracts.md) · [Security/trust](docs/security.md) · [Runbook](docs/runbook.md) · [Tests](docs/testing.md) · [Validation results](docs/validation.md) · [Performance](docs/performance.md) · [Coding guidelines](docs/coding.md) · [Research](docs/research.md) · [Third-party notice](vendor/NOTICE.md).

All authored code has purpose/function/class descriptions and CI-checked physical definition/parameter/variable line maps. The file guide below is generated from the exact tracked set, not a partial directory listing.

Accepted-source checks: 95 tests on Linux/macOS, 94 + one expected POSIX-only skip on Windows; 100% combined runtime coverage, actual no-uplink three-wheel installation, all seven validation/CodeQL jobs passed. See [actual evidence and limitations](docs/validation.md); badges track latest-main workflows separately.

## Complete file guide

<!-- BEGIN FILE GUIDE -->

| File | Purpose |
| --- | --- |
| [.gitattributes](.gitattributes) | Consistent LF text checkouts across operating systems. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Jason Stys: cross-platform signed delivery, actual no-uplink installation and independent scanners; no artifacts/caches. |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | Jason Stys: security-extended Python analysis; explicitly disable trap/dependency caches and database uploads. |
| [.gitignore](.gitignore) | Exclude local keys, environments, release bundles and private diagnostics. |
| [LICENSE](LICENSE) | MIT license for Jason Stys's authored code. |
| [README.md](README.md) | Disconnected Release Kit. |
| [docs/architecture.md](docs/architecture.md) | Architecture and ADR 001 — authenticated disconnected delivery. |
| [docs/coding.md](docs/coding.md) | Coding and documentation guidelines. |
| [docs/contracts.md](docs/contracts.md) | Release and deployment contracts. |
| [docs/performance.md](docs/performance.md) | Performance and complexity. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured bounded build/verification timing and Python allocation peak. |
| [docs/reports/ci.json](docs/reports/ci.json) | Actual immutable accepted-source CI snapshot, not a future guarantee. |
| [docs/reports/demo.json](docs/reports/demo.json) | Actual synthetic signed-release/tamper/rollback regression evidence. |
| [docs/reports/offline.json](docs/reports/offline.json) | Actual no-uplink Linux namespace wheelhouse installation evidence. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/research.md](docs/research.md) | Primary-source research and implementation choices. |
| [docs/review.md](docs/review.md) | Implementation review. |
| [docs/runbook.md](docs/runbook.md) | Operator runbook and release checklist. |
| [docs/security.md](docs/security.md) | Security model and limitations. |
| [docs/testing.md](docs/testing.md) | Testing strategy and acceptance criteria. |
| [docs/usage.md](docs/usage.md) | Usage and disconnected preparation. |
| [docs/validation.md](docs/validation.md) | Actual validation results. |
| [drkit/\_\_init\_\_.py](drkit/__init__.py) | Disconnected Release Kit: bounded signed offline delivery, created by Jason Stys. |
| [drkit/bundle.py](drkit/bundle.py) | Jason Stys: deterministic Ed25519-signed ZIP bundles with independent trust and bounded verification. |
| [drkit/cli.py](drkit/cli.py) | Jason Stys: explicit signing, verification and owned-root activation CLI; no auto-execution or key logging. |
| [drkit/contracts.py](drkit/contracts.py) | Jason Stys: strict release contracts, bounded canonical JSON and portable payload paths. |
| [drkit/deploy.py](drkit/deploy.py) | Jason Stys: owned-root staging, atomic activation, compare-and-swap and explicit non-destructive rollback. |
| [drkit/inventory.py](drkit/inventory.py) | Jason Stys: deterministic SPDX 2.3 blob/file inventory; no invented dependency or license claims. |
| [examples/service.py](examples/service.py) | Jason Stys: synthetic trusted offline application, no external data, network access or commands. |
| [pyproject.toml](pyproject.toml) | Jason Stys: strict typed signed-delivery runtime and branch coverage across every runtime module. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: complete test, type, format, dependency-audit and SPDX schema validation tools. |
| [requirements-dev.lock](requirements-dev.lock) | Universal full hash-locked development and independent audit graph. |
| [requirements.in](requirements.in) | Jason Stys: maintained Ed25519 implementation; no handwritten cryptographic primitive. |
| [requirements.lock](requirements.lock) | Universal full hash-locked offline runtime graph. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: bounded synthetic build/verify benchmark; no hardware-independent speed promises. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python AST definition/parameter/variable maps and lexical Bash/workflow line indexes. |
| [scripts/demo.py](scripts/demo.py) | Jason Stys: synthetic reproducibility, admission rejection and explicit rollback acceptance report. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/offline.sh](scripts/offline.sh) | Jason Stys: disposable CI-only loopback namespace; never alter the developer PC or host routes. |
| [scripts/offline\_prepare.py](scripts/offline_prepare.py) | Jason Stys: package reviewed source plus hash-locked platform wheels for an explicit disposable CI test. |
| [scripts/offline\_probe.py](scripts/offline_probe.py) | Jason Stys: actual no-uplink Linux namespace install of separately verified hash-locked wheelhouse. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: fail-closed tracked-file privacy, third-party schema integrity and no-storage workflow checks. |
| [tests/conftest.py](tests/conftest.py) | Jason Stys: isolated synthetic signing fixtures; no personal data or production trust. |
| [tests/test\_boundaries.py](tests/test_boundaries.py) | Jason Stys: independent staging/aggregate-cap, encrypted flag and trusted-floor rollback boundaries. |
| [tests/test\_bundle.py](tests/test_bundle.py) | Jason Stys: authenticated content, deterministic layout, malicious ZIPs and no-self-trust regressions. |
| [tests/test\_cli.py](tests/test_cli.py) | Jason Stys: complete explicit CLI lifecycle, safe failures and standalone module entry point. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: exact schema, time, path, canonical JSON and property-based admission boundaries. |
| [tests/test\_deploy.py](tests/test_deploy.py) | Jason Stys: atomic pointer, crash residue, CAS, rollback and immutable retained-byte regressions. |
| [tests/test\_inventory.py](tests/test_inventory.py) | Jason Stys: independent official SPDX schema checks and exact blob checksum relationships. |
| [tools.lock.json](tools.lock.json) | Official Linux scanner versions, URLs and SHA256 digests. |
| [vendor/NOTICE.md](vendor/NOTICE.md) | Third-party SPDX schema notice. |
| [vendor/SPDX-LICENSE.txt](vendor/SPDX-LICENSE.txt) | Unmodified upstream CC-BY-3.0 license for the vendored SPDX schema. |
| [vendor/spdx-schema.json](vendor/spdx-schema.json) | Immutable upstream SPDX 2.3.1 JSON schema; third-party CC-BY-3.0. |

<!-- END FILE GUIDE -->
