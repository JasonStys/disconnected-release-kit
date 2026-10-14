# Operator runbook and release checklist

Created by Jason Stys. Local owned lab, no production service deployment.

## Before transfer

Confirm target product/platform/Python, source revision, review, full dependency hashes/audit, license inventory, clean staging, signer/public-key fingerprint, realistic expiry/trusted time and minimum sequence. Run tests and scans. Provision verifier and trust separately. Do not package credentials or personal files. Keep signed bundle checksum and approved release record outside the transported media.

## Stage and activate

Use a new user-private root; verify ACLs/encryption appropriate to your OS. Back up current state and retained releases privately. Pass exact expected current digest. Verify staged content before pointer commit. Supervisor/application restart is an external integration; inspect real health before promoting. The lab's ready response is synthetic, not a production health check.

## Rollback triggers and action

Stop promotion for checksum/signature/expiry/policy error, failed pip check, unexpectedly missing runtime/toolchain or failed reviewed health test. Select an explicitly approved still-valid retained digest, pass expected current and current trust policy. Preserve the highest sequence. If an older release is expired, issue a reviewed newly signed higher-sequence recovery release rather than disabling the clock/signature checks.

## Interrupted operations

A process crash may leave operation.lock, state.pending or an unactivated digest directory. Do not auto-delete or overwrite them. Establish no operator/process is still writing; compare state, signed archive and payloads, archive evidence privately, then perform an explicit approved recovery in a fresh root if necessary. The toolkit retains releases and does not implement destructive cleanup.

## Publication acceptance

Check cross-platform tests, schema/properties, actual no-uplink install, ruff/mypy, tracked-file privacy/maps/inventory, Gitleaks, actionlint, ShellCheck, dependency audit and CodeQL. Confirm latest main SHA jobs—not only an old accepted snapshot. Record actual results/limitations and zero Actions artifact/cache additions. Monitor account storage before triggering Actions; cleanup requires a fresh approval.
