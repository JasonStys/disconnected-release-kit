# Architecture and ADR 001 — authenticated disconnected delivery

Created by Jason Stys. Status: accepted for this portfolio lab, 2026-10-14.

## Trust and sequence

```text
Trusted build source + signing key -> canonical manifest + signed exact file inventory -> deterministic ZIP
Untrusted transfer -> external trust + operator policy -> bounded verifier -> staged digest-named release
Staged full-byte verification -> CAS atomic state pointer -> explicit operator-controlled application use
Retained release + explicit current/target selection -> revalidation -> rollback pointer (floor preserved)
```

The signer and verifier are Python; the maintained cryptography package implements Ed25519. Bash is used only for lifecycle of a disposable Linux network namespace, not archive parsing or crypto. Native wheels are carried, never compiled on an offline target. No needless language split/network/API is added.

## Decisions and alternatives

| Decision | Reason / consequence |
| --- | --- |
| Ed25519 + independent public trust | Real authenticity with a maintained primitive. Raw demo keys are unencrypted; production signing/key custody is external. |
| Bounded in-memory ZIP_STORED | Deterministic, canonical-layout comparison and no decompression expansion. 64 MiB archives, 48 MiB input payload cap; unsuitable for huge images. |
| Custom small manifest | Clear teachable contract. Not TUF; lacks threshold trust, key rotation/revocation distribution, distributed metadata and resilient time. |
| SPDX blob/file inventory | Interoperable machine-readable carried bytes. No inferred license scan or complete dependency relationship graph. |
| Atomic JSON pointer + retained directories | Small cross-platform failure model. Existing services need their own atomic pointer reader/restart adapter. No host service is modified. |
| Hash-locked platform wheelhouse | pip verifies exact accepted wheels with no index. One prepared OS/architecture/Python target per bundle; not universal dependency portability. |
| Owned no-uplink namespace in CI | Actual egress-free pip installation without changing this PC/Docker. Not an air-gapped VM/filesystem/process sandbox. |

## Failure semantics

The root must not exist at initialization. Activation locks, verifies, checks sequence and expected current, creates a new digest directory, writes payloads, revalidates installed bytes, flushes the pending state and replaces state.json. Failure before replacement leaves the old pointer; partial releases/pending state are retained for inspection. Power failure can affect filesystem durability: directory metadata/payload fsync is not promised. Operation locks survive process death for deliberate manual handling.

Rollback never deletes files or reduces highest_sequence. It requires the target already in history and different from the expected current. Expired or below-operator-floor targets remain rejected. Retained directories are content-addressed, not OS-enforced write-once storage; revalidation detects changed bytes. The local owner controls state/trust; privileged host compromise is outside this model.
