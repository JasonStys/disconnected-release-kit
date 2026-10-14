# Release and deployment contracts

Created by Jason Stys. Exact manifest schema 1; no implicit coercion or ignored fields.

## Manifest

`schema, product, version, sequence, target, created, expires, source_revision, files`.
Product/target: lowercase ASCII IDs, 1–48 characters. Version: exact bounded x.y.z with no leading zeros except 0. Sequence: integer 1..2^31-1, not bool/float. Epoch time: 0..4102444800; lifetime positive and at most seven days. source_revision: lowercase 40-hex caller label, **not** proof of checkout provenance.

Each sorted descriptor has exact `path, size, sha256`. SHA256 is lowercase 64-hex. At least one payload and inventory.spdx.json; at most 254 descriptors. Noncanonical JSON, duplicate keys, extra fields and wrong types fail. This integer-only application canonical JSON profile is not advertised as RFC 8785/JCS.

## Archive/file limits

64 MiB entire archive and total decoded members; 16 MiB each file; manifest 128 KiB; at most 256 ZIP entries. Builder/staging input payload at most 48 MiB, reserving headroom for inventory/metadata. ZIP_STORED regular-file mode 0644, fixed 1980 timestamp, sorted member names. Canonical re-encoding rejects prefix/suffix/comments/different layouts even when the ZIP parser tolerates them.

Payload names start payload/, 2–5 components, ASCII letters/digits/underscore first, then letters/digits/underscore/dot/hyphen, each at most 128 characters; total at most 240. This permits genuine multi-platform-tag wheel filenames. No absolute paths, dot components, backslashes, drive letters, trailing dots, Windows devices, hidden dot names, .key/.pem/.env or __pycache__. Case-insensitive collisions and any file-as-directory ancestor collision fail. Name checks do not detect every possible secret in ordinary file content.

Central-directory size is capped at 128 KiB before ZIP parsing; end-of-central-directory must be the final fixed 22 bytes, with matching bounded member counts, one volume, no ZIP64/comment and exact directory bounds. Staging also caps visited directory entries at 512 and validates directory depth before descending.

## Authentication/admission

A signature is exactly 64 bytes; public/private raw Ed25519 keys are exactly 32 bytes. Signed bytes: domain `disconnected-release-kit/v1\0` followed by exact canonical manifest. No algorithm negotiation or bundled trust roots. Admit only matching independent product/target, created <= trusted now < expires, sequence >= operator floor. Validate every member size/hash and regenerate exact inventory. Generic verification performs no installation/execution.

## State/pointer

Owned root contains state.json, releases/<bundle-sha256>/ and a transient operation.lock. State fields: schema=1, current (null or known digest), highest_sequence, history (max 1000 digest entries). Normal activation sequence must strictly exceed highest. Compare expected current to avoid lost updates. Release directory name must equal the stored authenticated archive SHA256. Only explicit rollback may select an older retained version; floor stays unchanged. This is owner-trusted state, not hardware monotonic or remotely signed state.
