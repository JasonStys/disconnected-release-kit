# Security model and limitations

Created by Jason Stys. Use authorized reviewed software and approved removable media only.

## Assets, threats and defenses

Protect source integrity, signing/trust separation, release correctness and current-pointer consistency against modified transfer media, invalid archive paths, wrong signer, stale/mixed files, expiry, unsafe size expansion and concurrent operator errors. Fixed error messages avoid echoing submitted keys/data. No outbound code path exists in the runtime; online dependency/scanner preparation is explicitly separate.

Independent trust must be provisioned through an approved channel with public-key fingerprint verification. An attacker replacing both public key and bundle defeats authenticity. A compromised signer can sign harmful but valid software; signature checks are not malware detection. Secret scanning happens **before** building and never substitutes for human review. Signed data is not encrypted.

Raw demo private keys are intentionally unencrypted and ephemeral/ignored. POSIX modes are restrictive; Windows privacy depends on inherited user ACLs and disk encryption. Do not use demo-keygen for production key custody. Use an external signer/HSM-reviewed integration, approvals and offline recovery policy before production.

## Explicit limits

No TUF/SLSA/FIPS/ATO certification, threshold signing, online transparency, revocation/rotation service, malware scanning, reliable clock distribution, privilege separation, authenticated operator UI, hostile-host race sandbox, guaranteed power-loss durability, universal wheel portability, service supervisor, automatic rollback health monitor or automatic retention purge. Owner-controlled clock/state/trust may be changed by the owner. Avoid network/shared filesystems for deployment roots.

The CI namespace has only loopback and no main routes, but shares the disposable runner filesystem/kernel. It demonstrates network-disconnected installation, not a physically air-gapped infrastructure assurance assessment. It runs only the reviewed synthetic example; arbitrary payloads remain inert.

## CI boundary

Pinned Actions commits, minimum permissions, checkout credentials not persisted, pull_request (not pull_request_target), explicit timeouts, full-graph hash locks, pip audit, Gitleaks, actionlint, ShellCheck and CodeQL. No artifact uploads, Actions caches, CodeQL trap/dependency cache or database uploads. CI logs contain only synthetic public evidence; do not paste account billing/private diagnostics into this repo.

## Reporting

For a suspected vulnerability, contact Jason Stys through [GitHub](https://github.com/JasonStys) or [LinkedIn](https://www.linkedin.com/in/jason-stys-31b30b351/). Do not post private keys, personal data or exploitable production deployment details publicly.
