"""Jason Stys: authenticated candidate/active inventory review and non-executing transfer-review receipt."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: review — line 43
# parameter: root — line 44
# parameter: archive — line 45
# parameter: trusted — line 46
# parameter: policy — line 47
# parameter: expected — line 48
# parameter: operator — line 49
# parameter: medium_reference — line 50
# variable: old — line 61
# variable: candidate — line 63
# variable: active — line 64
# variable: before — line 69
# variable: after — line 70
# variable: rows — line 71
# variable: name — line 72
# variable: left — line 73
# variable: right — line 73
# variable: eligible — line 90
# variable: result — line 94
# definition: publish — line 125
# parameter: output — line 125
# parameter: result — line 125
# variable: target — line 127
# variable: p — line 129
# variable: text — line 133
# variable: page — line 135
# END CODE MAP

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from drkit.bundle import verify
from drkit.contracts import ID, Policy, canonical, require, sha
from drkit.deploy import locked, state, validate_installed


def review(
    root: Path,
    archive: bytes,
    trusted: bytes,
    policy: Policy,
    expected: str | None,
    operator: str,
    medium_reference: str,
) -> dict[str, Any]:
    """Authenticate exact candidate and full installed active tree under one owned lock; never stage, execute or change pointers."""
    require(
        isinstance(operator, str)
        and bool(ID.fullmatch(operator))
        and isinstance(medium_reference, str)
        and bool(ID.fullmatch(medium_reference)),
        "bounded review aliases required",
    )
    with locked(root):
        old = state(root)
        require(old["current"] == expected, "active digest changed")
        candidate = verify(archive, trusted, policy)
        active = (
            validate_installed(root / "releases" / expected, trusted, policy)
            if expected is not None
            else None
        )
        before = active.files if active else {}
        after = candidate.files
        rows = []
        for name in sorted(before.keys() | after.keys()):
            left, right = before.get(name), after.get(name)
            rows.append(
                {
                    "path": name,
                    "change": "ADDED"
                    if left is None
                    else "REMOVED"
                    if right is None
                    else "UNCHANGED"
                    if left == right
                    else "CHANGED",
                    "active_sha256": sha(left) if left is not None else None,
                    "candidate_sha256": sha(right) if right is not None else None,
                    "active_bytes": len(left) if left is not None else None,
                    "candidate_bytes": len(right) if right is not None else None,
                }
            )
        eligible = (
            candidate.metadata["sequence"] > old["highest_sequence"]
            and len(old["history"]) < 1000
        )
        result = {
            "schema": 1,
            "kind": "authenticated_transfer_review",
            "author": "Jason Stys",
            "active_digest": expected,
            "candidate_digest": candidate.digest,
            "active_sequence": active.metadata["sequence"] if active else None,
            "candidate_sequence": candidate.metadata["sequence"],
            "highest_sequence": old["highest_sequence"],
            "normal_activation_eligible_at_review": eligible,
            "trust_key_sha256": sha(trusted),
            "policy": {
                "product": policy.product,
                "target": policy.target,
                "now": policy.now,
                "minimum_sequence": policy.minimum_sequence,
            },
            "deployment_state_sha256": sha(canonical(old)),
            "files": rows,
            "scope": "Both signatures, manifests, SPDX inventories and every installed active byte were checked. File paths/sizes/hashes are metadata; payloads never execute. This is a review, not activation, physical transfer proof, malware certification or a signed human identity assertion. Activation must independently revalidate current state, trust, expiry and high-water sequence. A rollback does not reset the sequence floor.",
        }
        result["receipt"] = {
            "event": "VERIFIED_NONEXECUTING_REVIEW",
            "operator_alias": operator,
            "medium_reference_alias": medium_reference,
            "review_sha256": sha(canonical(result)),
            "claims": "Operator/media aliases are local assertions. No physical device or secret key was accessed; the receipt is not a digital signature.",
        }
        return result


def publish(result: dict[str, Any], output: Path) -> None:
    """Create a new private JSON/escaped inert review receipt; never replace deployment/evidence files."""
    target = output.absolute()
    require(
        not any(p.is_symlink() or p.is_junction() for p in (target, *target.parents)),
        "linked review output",
    )
    target.mkdir(mode=0o700)
    text = json.dumps(result, sort_keys=True, indent=2)
    (target / "review.json").write_text(text + "\n", encoding="utf-8")
    page = (
        '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; base-uri \'none\'; form-action \'none\'"><title>Authenticated transfer review — Jason Stys</title><main><h1>Authenticated transfer review</h1><p>Created by Jason Stys. Non-executing review; no physical transfer or activation is claimed.</p><pre>'
        + html.escape(text)
        + "</pre></main></html>"
    )
    (target / "review.html").write_text(page, encoding="utf-8")
