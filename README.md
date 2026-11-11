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

## Windows desktop workbench

The application provides real project controls, durable history and exact evidence export, created by Jason Stys. The one-file **DisconnectedReleaseKit.exe** bundles patched CPython 3.14.10, Tcl/Tk and the actual project runtime; end users need no Python, Node or command setup. This is a portable application, not an installer or an Authenticode-signed product. The source recipe and actual acceptance evidence are available now; public download/install status is a separate release decision.

Verify an authorized signed release ZIP against a separately provisioned raw 32-byte Ed25519 public key, product, target, explicit sequence floor and review clock. Or compare that candidate with an explicitly selected existing owned deployment and exact expected-current digest. The actual original verifier reauthenticates manifests, SPDX, every payload byte, expiry, trust and sequence; review reports added, removed, changed and unchanged inventory. Inspect eligibility and retained high-water scope, then export the exact saved report. Signing, deployment initialization, activation and rollback remain explicit original CLI operations.

[Desktop usage and privacy](docs/windows-app.md) · [Native validation record](docs/reports/native-workbench-2026-11-11.md). Existing CLI commands and explicit custom output paths remain supported.

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

## Review a transfer candidate before activation

```text
python -m drkit.cli review --root out/deployment --bundle out/candidate.zip --trusted-key out/trust.pub --product demo-service --target portable-source --expected <exact-current-digest-or-none> --operator reviewer-1 --medium-reference transfer-review-42 --out out/candidate-review
```

Use separately provisioned public trust and omit the synthetic `--now` clock in operational use. The review authenticates the candidate and reauthenticates every installed active byte/SBOM under the owned operation lock. It reports added, removed, changed and unchanged files, exact hashes/sizes, candidate/active sequences and the retained high-water sequence. Reusing or downgrading a sequence remains ineligible even after an explicit rollback. Nothing is staged, activated or executed; original activation must independently revalidate expiry, trust, sequence and expected-current state.

The new inert HTML/JSON contains a hash-bound non-executing review receipt with operator/media **aliases**. Those are local assertions, not authenticated human identity, physical transfer proof, a digital signature, malware certification or permission to run the bundle. Payload bytes and signing keys are excluded. The deployment pointer/history remain unchanged; only a temporary exclusive lock is acquired and released.

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
| [docs/handbook.md](docs/handbook.md) | Disconnected Release Kit handbook. |
| [docs/performance.md](docs/performance.md) | Performance and complexity. |
| [docs/reports/benchmark.json](docs/reports/benchmark.json) | Measured bounded build/verification timing and Python allocation peak. |
| [docs/reports/candidate-review-2026-11-09.md](docs/reports/candidate-review-2026-11-09.md) | Authenticated candidate review validation — November 9, 2026. |
| [docs/reports/ci.json](docs/reports/ci.json) | Actual immutable accepted-source CI snapshot, not a future guarantee. |
| [docs/reports/demo.json](docs/reports/demo.json) | Actual synthetic signed-release/tamper/rollback regression evidence. |
| [docs/reports/documentation-refresh-2026-11-09.md](docs/reports/documentation-refresh-2026-11-09.md) | Documentation refresh — 2026-11-09. |
| [docs/reports/native-workbench-2026-11-11.md](docs/reports/native-workbench-2026-11-11.md) | Native workbench validation — November 11, 2026. |
| [docs/reports/offline.json](docs/reports/offline.json) | Actual no-uplink Linux namespace wheelhouse installation evidence. |
| [docs/reports/portfolio-sync-2026-10-22.md](docs/reports/portfolio-sync-2026-10-22.md) | <!-- File: docs/reports/portfolio-sync-2026-10-22.md; Purpose: certificate-bundle security repair and evidence by Jason Stys. -->. |
| [docs/reports/project-guide.docx](docs/reports/project-guide.docx) | Reviewed source-bound Word guide with dated validation observations and practical limits. |
| [docs/reports/publications.json](docs/reports/publications.json) | Exact publication hashes, reviewed page identities and source/evidence baselines. |
| [docs/reports/runner-network-2026-11-11.md](docs/reports/runner-network-2026-11-11.md) | Disposable-runner package acquisition — 2026-11-11. |
| [docs/research.md](docs/research.md) | Primary-source research and implementation choices. |
| [docs/review.md](docs/review.md) | Implementation review. |
| [docs/runbook.md](docs/runbook.md) | Operator runbook and release checklist. |
| [docs/security.md](docs/security.md) | Security model and limitations. |
| [docs/testing.md](docs/testing.md) | Testing strategy and acceptance criteria. |
| [docs/usage.md](docs/usage.md) | Usage and disconnected preparation. |
| [docs/validation.md](docs/validation.md) | Actual validation results. |
| [docs/windows-app.md](docs/windows-app.md) | Windows application: disconnected-release-kit. |
| [drkit/\_\_init\_\_.py](drkit/__init__.py) | Disconnected Release Kit: bounded signed offline delivery, created by Jason Stys. |
| [drkit/bundle.py](drkit/bundle.py) | Jason Stys: deterministic Ed25519-signed ZIP bundles with independent trust and bounded verification. |
| [drkit/cli.py](drkit/cli.py) | Jason Stys: explicit signing, verification and owned-root activation CLI; no auto-execution or key logging. |
| [drkit/contracts.py](drkit/contracts.py) | Jason Stys: strict release contracts, bounded canonical JSON and portable payload paths. |
| [drkit/deploy.py](drkit/deploy.py) | Jason Stys: owned-root staging, atomic activation, compare-and-swap and explicit non-destructive rollback. |
| [drkit/desktop.py](drkit/desktop.py) | Native offline workbench: real project inputs, analysis, searchable evidence, history and export. Jason Stys. |
| [drkit/desktop\_io.py](drkit/desktop_io.py) | Bounded regular descriptor reads and strict finite JSON for owner-local desktop state. Jason Stys. |
| [drkit/desktop\_project.py](drkit/desktop_project.py) | Independent-trust signed-bundle verification and nonexecuting transfer review GUI. Jason Stys. |
| [drkit/desktop\_state.py](drkit/desktop_state.py) | Owner-local desktop profile, bounded durable bundles and non-overwriting export. Jason Stys. |
| [drkit/inputs.py](drkit/inputs.py) | Bounded stable ordinary-file reads and streaming tool hashes for offline identity inputs. Jason Stys. |
| [drkit/inventory.py](drkit/inventory.py) | Jason Stys: deterministic SPDX 2.3 blob/file inventory; no invented dependency or license claims. |
| [drkit/review.py](drkit/review.py) | Jason Stys: authenticated candidate/active inventory review and non-executing transfer-review receipt. |
| [examples/service.py](examples/service.py) | Jason Stys: synthetic trusted offline application, no external data, network access or commands. |
| [licenses/OpenSSL-4.0.3-LICENSE.txt](licenses/OpenSSL-4.0.3-LICENSE.txt) | Unmodified Apache-2.0 license from the exact OpenSSL 4.0.3 source tag used by the cryptography wheel. |
| [licenses/README.md](licenses/README.md) | Bundled cryptographic runtime notices. |
| [licenses/RUST-COPYRIGHT-library.html](licenses/RUST-COPYRIGHT-library.html) | Actual Rust1.98.1 standard-library copyright inventory matching the compiler-source identity embedded in the crypto wheel. |
| [licenses/cryptography-50.0.2-rust-inventory.json](licenses/cryptography-50.0.2-rust-inventory.json) | Minimal exact-wheel Rust component, archive and original-notice byte identities; provider private build paths omitted. |
| [licenses/cryptography-50.0.2-rust-notices.txt](licenses/cryptography-50.0.2-rust-notices.txt) | Exact32crate/62original notice texts from checksum-verified registry archives, conservative provider-SBOM scope. |
| [pyproject.toml](pyproject.toml) | Jason Stys: strict typed signed-delivery runtime and branch coverage across every runtime module. |
| [requirements-dev.in](requirements-dev.in) | Jason Stys: complete test, type, format, dependency-audit and SPDX schema validation tools. |
| [requirements-dev.lock](requirements-dev.lock) | Universal full hash-locked development and independent audit graph. |
| [requirements-native.lock](requirements-native.lock) | Exact hash-locked portable freezer graph, separate from the project runtime. |
| [requirements.in](requirements.in) | Jason Stys: maintained Ed25519 implementation; no handwritten cryptographic primitive. |
| [requirements.lock](requirements.lock) | Universal full hash-locked offline runtime graph. |
| [scripts/benchmark.py](scripts/benchmark.py) | Jason Stys: bounded synthetic build/verify benchmark; no hardware-independent speed promises. |
| [scripts/build\_native.py](scripts/build_native.py) | Build the complete real offline workbench as one Windows portable executable. Jason Stys. |
| [scripts/check\_tk\_runtime.py](scripts/check_tk_runtime.py) | Require the selected interpreter's actual native Tk imports and loaded Tcl, without a display. Jason Stys. |
| [scripts/code\_map.py](scripts/code_map.py) | Jason Stys: exact Python AST definition/parameter/variable maps and lexical Bash/workflow line indexes. |
| [scripts/demo.py](scripts/demo.py) | Jason Stys: synthetic reproducibility, admission rejection and explicit rollback acceptance report. |
| [scripts/file\_guide.py](scripts/file_guide.py) | Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses. |
| [scripts/native\_acceptance.py](scripts/native_acceptance.py) | Actual final portable widgets/core/native-window acceptance with independent oracles. Jason Stys. |
| [scripts/native\_common.py](scripts/native_common.py) | Actual patched Python/Tcl/Tk/PyInstaller runtime notices and authored portable icon. Jason Stys. |
| [scripts/native\_entry.py](scripts/native_entry.py) | Launch the actual bundled offline project workbench; no setup shell commands. Jason Stys. |
| [scripts/offline.sh](scripts/offline.sh) | Jason Stys: disposable CI-only loopback namespace; never alter the developer PC or host routes. |
| [scripts/offline\_prepare.py](scripts/offline_prepare.py) | Jason Stys: package reviewed source plus hash-locked platform wheels for an explicit disposable CI test. |
| [scripts/offline\_probe.py](scripts/offline_probe.py) | Jason Stys: actual no-uplink Linux namespace install of separately verified hash-locked wheelhouse. |
| [scripts/publication\_text.py](scripts/publication_text.py) | Jason Stys: inspect only named reviewed Office editions without hiding their XML. |
| [scripts/runtime\_terms.py](scripts/runtime_terms.py) | Verify captured original crypto/Rust terms against the actual installed wheel on each build OS. Jason Stys. |
| [scripts/scanners.py](scripts/scanners.py) | Install only hash-pinned official Linux scanner binaries. Created by Jason Stys. |
| [scripts/test\_native\_app.py](scripts/test_native_app.py) | Run the real frozen workbench twice with an owned synthetic profile and exact bundle persistence. Jason Stys. |
| [scripts/validate\_repo.py](scripts/validate_repo.py) | Jason Stys: fail-closed tracked-file privacy, third-party schema integrity and no-storage workflow checks. |
| [tests/conftest.py](tests/conftest.py) | Jason Stys: isolated synthetic signing fixtures; no personal data or production trust. |
| [tests/test\_boundaries.py](tests/test_boundaries.py) | Jason Stys: independent staging/aggregate-cap, encrypted flag and trusted-floor rollback boundaries. |
| [tests/test\_bundle.py](tests/test_bundle.py) | Jason Stys: authenticated content, deterministic layout, malicious ZIPs and no-self-trust regressions. |
| [tests/test\_bundle\_input.py](tests/test_bundle_input.py) | Actual same-descriptor regular-file and nonblocking FIFO admission for signed inputs. Jason Stys. |
| [tests/test\_cli.py](tests/test_cli.py) | Jason Stys: complete explicit CLI lifecycle, safe failures and standalone module entry point. |
| [tests/test\_contracts.py](tests/test_contracts.py) | Jason Stys: exact schema, time, path, canonical JSON and property-based admission boundaries. |
| [tests/test\_deploy.py](tests/test_deploy.py) | Jason Stys: atomic pointer, crash residue, CAS, rollback and immutable retained-byte regressions. |
| [tests/test\_desktop\_gui.py](tests/test_desktop_gui.py) | Presentation-adapter unit tests with real core/SQLite workers; real widgets are separately frozen-tested. Jason Stys. |
| [tests/test\_desktop\_io.py](tests/test_desktop_io.py) | Private state JSON and bounded descriptor-read boundary cases with actual file bytes. Jason Stys. |
| [tests/test\_desktop\_project.py](tests/test_desktop_project.py) | Actual independent signatures, transfer/CAS/floor and nonmutation GUI oracles. Jason Stys. |
| [tests/test\_desktop\_state.py](tests/test_desktop_state.py) | Independent offline desktop ownership, byte-bound, SQLite and non-overwrite regressions. Jason Stys. |
| [tests/test\_inventory.py](tests/test_inventory.py) | Jason Stys: independent official SPDX schema checks and exact blob checksum relationships. |
| [tests/test\_native\_inputs.py](tests/test_native_inputs.py) | Actual same-descriptor input bounds and ownership-change cases for selected offline reports. Jason Stys. |
| [tests/test\_profile\_admission.py](tests/test_profile_admission.py) | Actual pre-existing alias refusal and ordinary SQLite recovery continuity. Jason Stys. |
| [tests/test\_publication\_text.py](tests/test_publication_text.py) | Jason Stys: actual Office ZIP fixtures retain text scanning and reject unknown content. |
| [tests/test\_review.py](tests/test_review.py) | Jason Stys: authenticated inventory impact and non-executing review receipt regressions. |
| [tests/test\_runner\_network\_policy.py](tests/test_runner_network_policy.py) | Actual workflow policy mutants for signed disposable-runner APT acquisition. Jason Stys. |
| [tests/test\_runtime\_terms.py](tests/test_runtime_terms.py) | Independent changed-inventory/compiler/notice refusal cases; actual native packaging observes the real wheel. Jason Stys. |
| [tests/test\_tk\_runtime.py](tests/test_tk_runtime.py) | Actual isolated native Tcl positive plus fail-closed loader/interpreter/version controls. Jason Stys. |
| [tools.lock.json](tools.lock.json) | Official Linux scanner versions, URLs and SHA256 digests. |
| [vendor/NOTICE.md](vendor/NOTICE.md) | Third-party SPDX schema notice. |
| [vendor/SPDX-LICENSE.txt](vendor/SPDX-LICENSE.txt) | Unmodified upstream CC-BY-3.0 license for the vendored SPDX schema. |
| [vendor/spdx-schema.json](vendor/spdx-schema.json) | Immutable upstream SPDX 2.3.1 JSON schema; third-party CC-BY-3.0. |

<!-- END FILE GUIDE -->

## Documentation editions

Start with the [organized handbook](docs/handbook.md) for current usage, design, security and test guidance. Reviewed downloadable editions: [project-guide.docx](docs/reports/project-guide.docx).

[Publication identities and source scope](docs/reports/publications.json) · [Documentation validation record](docs/reports/documentation-refresh-2026-11-09.md). Historical results retain their own tested revision and date.
