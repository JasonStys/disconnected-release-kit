# Usage and disconnected preparation

Created by Jason Stys. Python 3.12+, maintained cryptography runtime and separately trusted public key are required **before** verifying a received release.

## Explicit CLI demo

From the repository root with its environment active:

```text
mkdir out
python -m drkit.cli demo-keygen --out out/demo-keys
python -m drkit.cli build --source examples --private-key out/demo-keys/demo.key --out out/demo.zip --product demo-service --target portable-source --version 1.0.0 --sequence 1 --created 1700000000 --expires 1700003601 --revision aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
python -m drkit.cli verify --bundle out/demo.zip --trusted-key out/demo-keys/trust.pub --product demo-service --target portable-source --now 1700000001
python -m drkit.cli init --root out/demo-deployment
python -m drkit.cli activate --root out/demo-deployment --bundle out/demo.zip --trusted-key out/demo-keys/trust.pub --product demo-service --target portable-source --now 1700000001 --expected none
python -m drkit.cli status --root out/demo-deployment
```

These are **expired synthetic frozen-clock examples**, not an operational release. Use fresh real created/expires epochs and omit --now operationally. Use the real checkout revision, not the synthetic repeated-a label. Build outputs refuse overwrites. Do not include keys or whole personal/workspace directories as staging sources.

Build next release with sequence 2 and a distinct reviewed source/version. Activate with --expected <exact-current-digest>. Rollback:

```text
python -m drkit.cli rollback --root out/demo-deployment --release <retained-target-digest> --expected <current-digest> --trusted-key out/demo-keys/trust.pub --product demo-service --target portable-source --now 1700000001
```

## Connected preparation and offline target

1. Review/audit source, runtime lock, licenses, target platform and transfer authorization.
2. On a matching OS/architecture/Python preparation system: `python -m pip download --only-binary=:all: --require-hashes -r requirements.lock --dest out/wheels`. Verify exact locked wheels; audit graph while online.
3. Package reviewed source, requirements.lock and those wheels in an explicit clean staging folder. Use real signing infrastructure and approved public-key distribution outside the bundle. Wheel/license redistribution obligations remain the operator's responsibility.
4. Preprovision trusted Python, verifier/cryptography and public key on the target. Bundle-verifies-itself from untrusted downloaded code is **not** a secure bootstrap.
5. Independently verify/activate the bundle. Create a fresh virtual environment. Run pip with `--no-index --only-binary=:all: --find-links <verified-wheelhouse> --require-hashes -r <verified-requirements.lock>`; then `pip check`. No offline pip-audit promise: advisory databases require separately prepared approved snapshots.
6. An approved supervisor/operator may then run the exact reviewed application; toolkit activation alone never executes it.

Actual no-uplink steps are automated in the Linux Actions job. scripts/offline.sh refuses ordinary local usage; no local root/Docker/network repair is requested.
