# Primary-source research and implementation choices

Reviewed 2026-10-14 by Jason Stys. Primary technical documentation, not marketing/security certification claims.

- [cryptography 50.0.2 Ed25519](https://cryptography.io/en/50.0.2/hazmat/primitives/asymmetric/ed25519/): maintained key generation/sign/verify and raw 32-byte serialization; use directly, no custom primitive.
- [pip secure installs](https://pip.pypa.io/en/stable/topics/secure-installs/), [repeatable installs](https://pip.pypa.io/en/stable/topics/repeatable-installs/), [pip install](https://pip.pypa.io/en/stable/cli/pip_install/): pin/hash the transitive graph; platform wheelhouses plus --no-index are explicitly demonstrated.
- [SPDX 2.3.1 specification](https://spdx.github.io/spdx-spec/v2.3.1/), [official immutable JSON schema](https://github.com/spdx/spdx-spec/blob/6f2cb47d13db19b12c23885573b22ef32ec1ada5/schemas/spdx-schema.json): interoperability checks for file/wheel blobs; no licensing assertions or inferred dependency claims.
- [TUF specification](https://theupdateframework.github.io/specification/latest/): independent initial trust, expiration, rollback/resource controls motivate this smaller design; it is explicitly not a TUF client or repository.
- [Python zipfile](https://docs.python.org/3/library/zipfile.html), [os.replace](https://docs.python.org/3/library/os.html#os.replace): use bounded regular members without extractall and atomic pointer replacement; not full filesystem power-loss durability.

Runtime/dev dependency versions were resolved with uv 0.13.1 into universal complete hash locks and audited in CI. Scanner binaries use official GitHub release URLs and pinned checksums in tools.lock.json. GitHub Actions use immutable commit references; hosted-runner kernel/IP tools are not claimed hermetic across time. Exact accepted evidence is recorded separately from latest workflow badges.
