# Actual validation results

Created by Jason Stys, 2026-10-14.

Accepted implementation revision: **53014a45af4ef0eafa4da32ad798d660ae2f57a7**. [Validate run](https://github.com/JasonStys/disconnected-release-kit/actions/runs/38609277079): all six jobs passed. [CodeQL run](https://github.com/JasonStys/disconnected-release-kit/actions/runs/38609276722): Python security-extended analysis passed, zero open alerts.

| Actual check | Result |
| --- | --- |
| Linux Python 3.12 / 3.14 and macOS Intel 3.14 | 95 tests passed on each environment. |
| Windows Python 3.14 | 94 passed, one expected real POSIX symlink privilege skip; simulated Windows junction guards tested. |
| All six runtime modules | 100% combined coverage: 397 statements, 58 branches; no coverage exclusions. |
| Synthetic signed release | Identical same-key/input bytes, ten negative cases rejected, two activations, explicit rollback preserves highest_sequence=2 and both releases. |
| Actual Linux no-uplink namespace | Only loopback, zero IPv4/IPv6 main routes, reserved-address connect blocked; three hash-locked wheels installed with no index, pip check passed, fresh environment reverified signed bundle, trusted synthetic app ready. |
| Namespace cleanup | Exact newly owned namespace removed and absence checked. Host routes/Docker/PC security settings unchanged. |
| Quality and independent validation | ruff, strict mypy, header/file maps, privacy/storage guard, official SPDX schema validation and property tests passed. |
| Security tools | pip-audit found no known locked-graph vulnerabilities; Gitleaks, actionlint, ShellCheck and CodeQL passed. |
| Repo Actions storage | Zero artifacts and zero caches at acceptance. No upload-artifact/cache steps or CodeQL cache/database uploads. |

Machine-readable evidence: [CI snapshot](reports/ci.json), [delivery regression](reports/demo.json), [actual offline install](reports/offline.json), [benchmark](reports/benchmark.json). All are actual public synthetic results, with immutable source/run/job references. This document/report commit is later than the accepted implementation; latest-main workflows are separately rechecked before handoff rather than inventing a self-referential final hash.

Local Windows Python 3.14.6 also passed 94 tests/one expected skip, 100% runtime coverage and strict quality checks. A three-wheel --no-index/--require-hashes install in a new local virtual environment passed pip check, returned ready and reverified the signed snapshot; local networking was not disabled, so only the Linux namespace test establishes no-uplink installation evidence.

Initial run [38609063334](https://github.com/JasonStys/disconnected-release-kit/actions/runs/38609063334) failed before jobs because a YAML plain scalar contained colon-space in pip's :all: argument. actionlint reproduced the exact line; a block scalar fixed it in the accepted revision. Failed history remains visible. No tests or security checks were disabled to obtain green status.

These results are not exhaustive proof, physical-air-gap assurance, production signing/key management or compliance certification. Review [security limits](security.md) and [code review](review.md).
