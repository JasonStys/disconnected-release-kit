# Disconnected Release Kit handbook

By Jason Stys.

Review authenticated candidate/active installed bytes and SPDX inventory under owned locking with state/trust/policy-bound non-executing receipts.

Review authenticated candidate/active installed bytes and SPDX inventory under owned locking with state/trust/policy-bound non-executing receipts.

Supports offline release review without mistaking filenames or transfer completion for authenticity.

## Read the documentation

| Edition | Audience and contents |
| --- | --- |
| [project-guide.docx](reports/project-guide.docx) | User and developer guide: purpose, current usage, design, boundaries and source references. |

The editable Markdown remains the maintenance source. The Word files are readable editions. See [publication identities and review](reports/publications.json) and the [documentation refresh record](reports/documentation-refresh-2026-11-09.md).

## Current usage and help

[README quick start](../README.md) is the entry point. Use the project-specific guides below before changing inputs, operating modes or deployment assumptions.

### Usage and operations

- [review](review.md)
- [runbook](runbook.md)
- [usage](usage.md)

### Design and contracts

- [architecture](architecture.md)
- [contracts](contracts.md)
- [research](research.md)

### Security and validation

- [performance](performance.md)
- [security](security.md)
- [testing](testing.md)
- [validation](validation.md)

## Historical results and reproduction

The reviewed source is [`fc7251517c832ca6938ebf70b40a8ca13c593edf`](https://github.com/JasonStys/disconnected-release-kit/tree/fc7251517c832ca6938ebf70b40a8ca13c593edf). The observed functional workflow baseline is `fc7251517c832ca6938ebf70b40a8ca13c593edf`; those observations are recorded at `2026-11-10T05:25:40.628667+00:00`. They do not certify an unrun later revision.

- [Detailed recorded validation](reports/candidate-review-2026-11-09.md)
- [Current Actions](https://github.com/JasonStys/disconnected-release-kit/actions) records later integration checks separately.
- Preserve dated measurements and follow the existing testing guide to reproduce them; a test-source inventory alone does not establish execution.

## Practical boundaries

- Operator/media aliases are assertions, not identity, physical-transfer proof or signatures.
- Review does not execute payloads or grant activation permission.
- Owned locks coordinate cooperating operations on a trusted filesystem, not a hostile administrator or arbitrary external writer.

## Maintaining these editions

Update the editable usage/design/test documents first. Rebuild and visually review every Word page and workbook tab before replacing an edition; verify the exact binary digests and evidence source in publications.json. Keep account data, logs with secrets, installed-app state and private test stores out of documentation. Source and release assets retain their existing security and licensing boundaries.


## Native desktop workbench

See [desktop controls and owner-local privacy](windows-app.md) and [dated actual native validation](reports/native-workbench-2026-11-11.md). Verification alone does not authenticate deployed state. Candidate comparison temporarily acquires the original owned deployment operation lock, revalidates active bytes and leaves the deployment pointer/history unchanged. GUI history is a separate SQLite transaction, not atomic with deployment state; review is not activation permission or malware certification. Operator/media aliases are assertions, not authentication or physical-transfer proof. Independent trust comes from outside the bundle. No signing-key picker, arbitrary payload execution, download or live deployment is exposed.
