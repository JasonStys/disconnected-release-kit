# Installed Windows 1.1.0: validation and user guide

By Jason Stys. 11 November 2026.

The independently downloaded installed application uses exact clean runtime source `22ba6c0b6ff464624f8b56ab1d9a19737cef6408`. Historical reports and Office editions remain unchanged.

## Purpose and practical improvements

Review signed offline release bundles using an independently supplied Ed25519 public key, explicit product and target identity, assessment time and sequence policy. Inspect a candidate against retained deployment evidence without activating it.

The original kit retains layered bundle signature, inventory, identity, expiration and rollback protections. The new GUI calls the same verifier, compares exact candidate and active bytes, records high-water and expected-current decisions, and supports complete no-overwrite exports and durable local history.

## Actual validation

**Independent distribution: Passed.** Downloaded provider assets, sidecar and installed file identities matched. The complete installed app was used; installation resources remained byte-identical.

**Actual app use and restart: Passed.** Ten actual workflows and ten complete evidence bundles passed the original installed consumer, including negative cases, no-overwrite export and two normal exits with exact retained history.

**Source and security: Passed.** All current main workflows passed before publication. All configured exact-source processed CodeQL categories had zero raw findings and zero open alerts.

**Individual shortcut: Verified.** Desktop and Start-menu targets were read back against the installed version. Normal default-profile shortcut activation is separate from full installed executable acceptance.

## Illustrated operation and implementation

The [four-page application guide](windows-application-guide-1.1.0.docx) contains two actual installed screenshots, a practical user journey and immutable code. Its [review manifest](windows-application-guide-1.1.0.json) records exact document, image, code and page identities.

Download the matching version and checksum from Releases. This is an unsigned per-user portable Windows x64 app; keep its complete accompanying files together. No system Python installation or Docker change is needed.

Use the individual Desktop icon and in-app help. Inputs, saved evidence and exports stay outside the installation. Preserve older versions and your own profiles; tests used only separate synthetic inputs.

The trust key must be established independently by the operator. A matching signature does not independently establish that a publisher or payload is safe.

The GUI does not sign, execute, activate or roll back payloads. These are separately controlled original CLI operations, not a claim made by a successful candidate review.

Only synthetic prepared inputs and isolated retained profiles were used. Ordinary user accounts and local Docker were not opened or changed. Shortcut target read-back and full installed-executable tests are separate from ordinary default-profile icon activation. This documentation revision still requires its own original hosted gates and processed security analyses.
