"""Independent-trust signed-bundle verification and nonexecuting transfer review GUI. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 113
# variable: PRODUCT — line 114
# variable: PROFILE — line 114
# variable: TITLE — line 115
# variable: VERSION — line 115
# variable: COLUMNS — line 116
# variable: RESOURCES — line 122
# variable: RESOURCE_LIMITS — line 128
# variable: MODES — line 129
# variable: REVIEW_MODE — line 134
# variable: CHOICES — line 135
# variable: FIELDS — line 147
# variable: ACTIVE_FIELDS — line 160
# variable: SCENARIOS — line 183
# variable: TEST_CLOCK — line 193
# variable: HELP — line 194
# definition: scenario — line 199
# parameter: name — line 199
# variable: index — line 203
# definition: policy — line 220
# parameter: parameters — line 220
# variable: raw_time — line 222
# variable: parsed — line 224
# variable: floor — line 233
# variable: result — line 236
# definition: prepared — line 246
# parameter: name — line 247
# parameter: stage — line 247
# parameter: trusted_policy — line 247
# variable: created — line 252
# variable: key — line 253
# variable: public — line 254
# variable: secret — line 254
# variable: initial — line 255
# variable: changed — line 259
# definition: archive — line 265
# parameter: files — line 265
# parameter: sequence — line 265
# variable: first — line 279
# variable: second — line 279
# variable: candidate — line 280
# variable: root — line 281
# variable: fixture_policy — line 283
# variable: current — line 287
# variable: candidate — line 292
# variable: candidate — line 294
# variable: candidate — line 296
# variable: candidate — line 298
# definition: analyze — line 303
# parameter: parameters — line 304
# parameter: stage — line 304
# parameter: workspace — line 304
# variable: mode — line 308
# variable: trusted_policy — line 311
# variable: expected — line 313
# variable: raw — line 313
# variable: root — line 313
# variable: trusted — line 313
# variable: raw — line 317
# variable: trusted — line 318
# variable: root — line 319
# variable: text — line 320
# variable: expected — line 323
# variable: accepted — line 325
# variable: result — line 326
# variable: data — line 342
# variable: name — line 342
# variable: raw_result — line 346
# variable: page — line 347
# variable: files — line 352
# variable: verdict — line 353
# variable: before — line 356
# variable: result — line 357
# variable: after — line 366
# variable: output — line 369
# variable: files — line 371
# variable: path — line 372
# variable: verdict — line 374
# definition: views — line 400
# parameter: files — line 400
# variable: result — line 402
# variable: row — line 403
# variable: rows — line 403
# variable: row — line 408
# variable: name — line 415
# variable: value — line 415
# definition: cells — line 422
# parameter: row — line 422
# END CODE MAP

from __future__ import annotations

import html
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .bundle import build, verify
from .contracts import DIGEST, MAX_BUNDLE, Policy, sha
from .deploy import activate, initialize, rollback
from .deploy import state as deployment_state
from .desktop_io import Rejected, canonical, json_value
from .desktop_state import Workspace
from .inputs import read_source
from .review import publish, review

ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
PRODUCT, PROFILE = "disconnected-release-kit", "DisconnectedReleaseKit"
TITLE, VERSION = "Disconnected Release Review Workbench", "1.1.0"
COLUMNS = (
    "File / evidence",
    "Active bytes / sequence",
    "Candidate bytes / sequence",
    "Change / admission",
)
RESOURCES = (
    "notices.txt",
    "app.ico",
    "python314.dll",
    "cryptography/hazmat/bindings/_rust.pyd",
)
RESOURCE_LIMITS: dict[str, int] = {}
MODES = (
    "Review prepared signed transfer scenario",
    "Verify authorized signed bundle",
    "Compare candidate with owned deployment",
)
REVIEW_MODE = None
CHOICES = {
    "transfer_case": (
        "initial",
        "added-and-changed",
        "removed-and-changed",
        "same-payload",
        "reused-sequence",
        "after-rollback",
        "higher-sequence",
        "trusted-floor",
    )
}
FIELDS = (
    ("transfer_case", "Inert signed-transfer exercise", "choice"),
    ("bundle", "Authorized signed ZIP bundle", "file"),
    ("trusted_key", "Separately provisioned raw 32-byte PUBLIC trust key", "file"),
    ("product", "Trusted product identifier", "text"),
    ("target", "Trusted target identifier", "text"),
    ("as_of", "UTC test clock YYYY-MM-DDTHH:MM:SSZ (blank: current)", "text"),
    ("minimum_sequence", "Independent minimum sequence, 0–2147483647", "text"),
    ("deployment", "Existing authorized owned deployment directory", "directory"),
    ("expected", "Exact expected active digest, or none", "text"),
    ("operator", "Nonsecret operator alias (not authentication)", "text"),
    ("medium", "Nonsecret transfer reference (not physical proof)", "text"),
)
ACTIVE_FIELDS = {
    MODES[0]: ("transfer_case", "as_of", "minimum_sequence", "operator", "medium"),
    MODES[1]: (
        "bundle",
        "trusted_key",
        "product",
        "target",
        "as_of",
        "minimum_sequence",
    ),
    MODES[2]: (
        "bundle",
        "trusted_key",
        "product",
        "target",
        "as_of",
        "minimum_sequence",
        "deployment",
        "expected",
        "operator",
        "medium",
    ),
}
SCENARIOS = (
    "Initial independently signed transfer",
    "Candidate adds and changes files",
    "Candidate removes and changes files",
    "New release retains payload bytes",
    "Reused sequence is ineligible",
    "Rollback retains the higher sequence floor",
    "Higher-sequence replacement is eligible",
    "Explicit independent sequence floor",
)
TEST_CLOCK = "2030-01-01T00:05:00Z"
HELP = """Verify authorized signed bundles with this project's actual Ed25519, canonical ZIP/manifest, path/size/hash/expiry/target/floor and SPDX inventory engine. Select a separately provisioned raw 32-byte PUBLIC trust key; the bundle never supplies its own trust. Enter your expected product/target and sequence floor. Blank as-of uses actual current UTC. Any entered timestamp is an explicit TEST CLOCK, not permission to bypass operational expiry. Prepared examples visibly select a frozen test clock and use newly generated ephemeral synthetic signing keys; no private key is retained or accepted by this GUI.
The comparison operation reauthenticates the candidate AND all installed active bytes under the original temporary owned-root operation lock. Enter the exact expected active digest or none; a stale expectation refuses the review. Inspect added/removed/changed/unchanged file hashes, active/candidate/high-water sequences and whether normal activation was eligible AT REVIEW TIME. An explicit rollback never resets the high-water mark. The GUI does not sign operational bundles, initialize a selected deployment, activate, roll back, execute payloads, install wheels, access a transfer device or change an OS service. Original explicit signing/activation/rollback CLI operations remain available and must independently revalidate current trust, expiry, sequence and CAS.
Operator/media aliases are local assertions, not authenticated identity, a signature, physical custody proof or malware certification. Search does not alter the full review. Reports retain metadata, not payload bytes or signing secrets; keep originals/trust separately. Saved owner-local history is plaintext, not encrypted or multiuser. Exit waits for the real verifier/review lock and committed evidence. SHA256 binds bytes; it does not establish safe code, compliance or a publisher signature on this application's EXE."""


def scenario(name: str) -> dict[str, str]:
    """Populate ordinary controls and an unmistakable explicit test clock; never silently activate a selected root."""
    if name not in SCENARIOS:
        raise Rejected("unknown signed-transfer exercise")
    index = SCENARIOS.index(name)
    return {
        "mode": MODES[0],
        "transfer_case": CHOICES["transfer_case"][index],
        "bundle": "",
        "trusted_key": "",
        "product": "demo-service",
        "target": "portable-source",
        "as_of": TEST_CLOCK,
        "minimum_sequence": "2" if index == 7 else "0",
        "deployment": "",
        "expected": "none",
        "operator": "local-reviewer",
        "medium": "synthetic-transfer",
    }


def policy(parameters: dict[str, str]) -> Policy:
    """Use independent explicit policy, never archive labels; malformed/test times cannot silently become current time."""
    raw_time = parameters.get("as_of", "").strip()
    try:
        parsed = (
            datetime.strptime(raw_time, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            if raw_time
            else None
        )
    except ValueError:
        raise Rejected("explicit UTC clock must match YYYY-MM-DDTHH:MM:SSZ") from None
    if parsed is not None and parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != raw_time:
        raise Rejected("noncanonical explicit UTC clock")
    floor = parameters.get("minimum_sequence", "").strip()
    if not floor.isascii() or not floor.isdecimal() or not 0 <= int(floor) <= 2**31 - 1:
        raise Rejected("invalid independent minimum sequence")
    result = Policy(
        parameters.get("product", ""),
        parameters.get("target", ""),
        int(parsed.timestamp()) if parsed else int(time.time()),
        int(floor),
    )
    result.validate()
    return result


def prepared(
    stage: Path, name: str, trusted_policy: Policy
) -> tuple[Path, bytes, bytes, str | None]:
    """Create only inert fresh stage fixtures, discard ephemeral private key; exercise ORIGINAL activation/rollback in that stage."""
    if name not in CHOICES["transfer_case"]:
        raise Rejected("unknown prepared transfer")
    created = 1893456000
    key = Ed25519PrivateKey.generate()
    secret, public = key.private_bytes_raw(), key.public_key().public_bytes_raw()
    initial = {
        "payload/config.json": b'{"report_units":"mm"}\n',
        "payload/readme.txt": b"Synthetic owned data; never execute.\n",
    }
    changed = {
        **initial,
        "payload/config.json": b'{"report_units":"mm","revision":2}\n',
        "payload/notes.txt": b"Synthetic reviewed transfer.\n",
    }

    def archive(files: dict[str, bytes], sequence: int) -> bytes:
        """Call the original real signing/inventory engine for bounded synthetic bytes only."""
        return build(
            files,
            secret,
            product="demo-service",
            version=f"1.{sequence}.0",
            sequence=sequence,
            target="portable-source",
            created=created,
            expires=created + 3600,
            revision="a" * 40,
        )

    first, second = archive(initial, 1), archive(changed, 2)
    candidate = second
    root = stage / "synthetic-deployment"
    initialize(root)
    fixture_policy = Policy("demo-service", "portable-source", trusted_policy.now, 0)
    if name not in ("initial", "trusted-floor"):
        activate(root, first, public, fixture_policy, None)
    if name in ("reused-sequence", "after-rollback"):
        current = deployment_state(root)["current"]
        activate(root, second, public, fixture_policy, current)
        if name == "after-rollback":
            rollback(root, sha(first), sha(second), public, fixture_policy)
    if name == "initial":
        candidate = first
    elif name == "removed-and-changed":
        candidate = archive({"payload/config.json": b'{"report_units":"cm"}\n'}, 2)
    elif name == "same-payload":
        candidate = archive(initial, 2)
    elif name == "higher-sequence":
        candidate = archive(changed, 3)
    # Ephemeral signing material remains local to this synthetic call and is never written or returned.
    return root, candidate, public, deployment_state(root)["current"]


def analyze(
    workspace: Workspace, parameters: dict[str, str], stage: Path
) -> tuple[str, str, dict[str, bytes]]:
    """Verify actual signatures/inventories or reauthenticate candidate/active bytes; never mutate the selected deployment pointer."""
    del workspace
    mode = parameters.get("mode", "")
    if mode not in MODES:
        raise Rejected("unsupported transfer operation")
    trusted_policy = policy(parameters)
    if mode == MODES[0]:
        root, raw, trusted, expected = prepared(
            stage, parameters.get("transfer_case", ""), trusted_policy
        )
    else:
        raw = read_source(Path(parameters.get("bundle", "")), MAX_BUNDLE)
        trusted = read_source(Path(parameters.get("trusted_key", "")), 32)
        root = Path(parameters.get("deployment", ""))
        text = parameters.get("expected", "")
        if mode == MODES[2] and text != "none" and DIGEST.fullmatch(text) is None:
            raise Rejected("exact expected digest or none is required")
        expected = None if text == "none" else text
    if mode == MODES[1]:
        accepted = verify(raw, trusted, trusted_policy)
        result = {
            "schema": 1,
            "kind": "authenticated_bundle_verification",
            "author": "Jason Stys",
            "candidate_digest": accepted.digest,
            "candidate_sequence": accepted.metadata["sequence"],
            "trust_key_sha256": sha(trusted),
            "metadata": accepted.metadata,
            "inventory": json_value(accepted.files["inventory.spdx.json"]),
            "files": [
                {
                    "path": name,
                    "candidate_bytes": len(data),
                    "candidate_sha256": sha(data),
                    "change": "VERIFIED_ONLY",
                }
                for name, data in sorted(accepted.files.items())
            ],
            "scope": "Actual independent-trust signature, manifest/inventory and payload hashes checked. No active deployment was inspected; no activation eligibility, malware safety or execution is established.",
        }
        raw_result = canonical(result)
        page = (
            '<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'"><title>Signed bundle review - Jason Stys</title><main><h1>Authenticated bundle metadata</h1><pre>'
            + html.escape(raw_result.decode())
            + "</pre></main></html>"
        )
        files = {"review.json": raw_result, "review.html": page.encode()}
        verdict = "authenticated data; no activation review"
    else:
        # The original review takes/releases its own lock and does not stage/activate/execute any candidate.
        before = read_source(root / "state.json", 65536)
        result = review(
            root,
            raw,
            trusted,
            trusted_policy,
            expected,
            parameters.get("operator", ""),
            parameters.get("medium", ""),
        )
        after = read_source(root / "state.json", 65536)
        if before != after:
            raise Rejected("deployment changed during nonexecuting review")
        output = stage / "review-output"
        publish(result, output)
        files = {
            path.name: read_source(path, 32 * 1024 * 1024) for path in output.iterdir()
        }
        verdict = (
            "eligible at review time"
            if result["normal_activation_eligible_at_review"]
            else "not eligible for normal activation"
        )
    files["input-scope.json"] = canonical(
        {
            "schema": 1,
            "origin": mode,
            "bundle_sha256": sha(raw),
            "trust_key_sha256": sha(trusted),
            "as_of_epoch": trusted_policy.now,
            "product": trusted_policy.product,
            "target": trusted_policy.target,
            "explicit_test_clock": bool(parameters.get("as_of", "").strip()),
            "minimum_sequence": trusted_policy.minimum_sequence,
            "scope": "No private key, payload bytes or source paths exported. Selected operational deployment pointer remains unchanged; signing/activation/rollback are separate CLI operations and require fresh independent revalidation.",
        }
    )
    return (
        "authenticated-transfer-review",
        f"{len(result['files'])} authenticated inventory files; candidate sequence {result['candidate_sequence']}; {verdict}",
        files,
    )


def views(files: dict[str, bytes]) -> dict[str, list[dict[str, Any]]]:
    """Keep complete change/sequence/trust/receipt scope visible separately from filtered file metadata."""
    result = json_value(files["review.json"])
    rows = [{"kind": "file", **row} for row in result["files"]]
    return {
        "Authenticated inventory and changes": rows,
        "Changed payload files": [
            row
            for row in rows
            if row["path"].startswith("payload/")
            and row["change"] in {"ADDED", "REMOVED", "CHANGED"}
        ],
        "Trust, sequences and review scope": [
            {
                "kind": "scope",
                **{name: value for name, value in result.items() if name != "files"},
            },
            {"kind": "input_scope", **json_value(files["input-scope.json"])},
        ],
    }


def cells(row: dict[str, Any]) -> tuple[str, str, str, str]:
    """Render literal metadata and eligibility, never imply a local alias authenticates a person."""
    if row.get("kind") == "file":
        return (
            str(row["path"]),
            str(row.get("active_bytes", "not inspected")),
            str(row.get("candidate_bytes", "removed")),
            str(row["change"]),
        )
    return (
        str(row.get("kind", "evidence")),
        str(row.get("active_sequence", "")),
        str(row.get("candidate_sequence", row.get("as_of_epoch", ""))),
        str(row.get("scope", "")),
    )
