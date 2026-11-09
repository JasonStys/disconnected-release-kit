"""Jason Stys: authenticated inventory impact and non-executing review receipt regressions."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_verified_diff_no_mutation_and_receipt — line 58
# parameter: policy — line 58
# parameter: root — line 58
# parameter: secret — line 58
# parameter: trusted — line 58
# variable: first — line 61
# variable: one — line 62
# variable: second — line 63
# variable: before — line 74
# variable: p — line 75
# variable: result — line 77
# variable: r — line 80
# variable: receipt — line 89
# variable: p — line 93
# definition: test_first_release_high_water_and_auth_failures — line 110
# parameter: policy — line 110
# parameter: root — line 110
# parameter: secret — line 110
# parameter: trusted — line 110
# variable: first — line 113
# variable: second — line 113
# variable: initial — line 114
# variable: r — line 116
# variable: one — line 118
# variable: two — line 119
# variable: wrong — line 135
# definition: test_cli_safe_output_and_aliases — line 161
# parameter: policy — line 161
# parameter: root — line 161
# parameter: secret — line 161
# parameter: tmp_path — line 161
# parameter: trusted — line 161
# variable: archive — line 164
# variable: key — line 166
# variable: out — line 168
# variable: args — line 169
# variable: original — line 193
# variable: operator — line 195
# variable: result — line 200
# END CODE MAP

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drkit.bundle import build
from drkit.cli import main
from drkit.contracts import Rejected, canonical, sha
from drkit.deploy import activate, initialize, rollback, state
from drkit.review import publish, review
from tests.conftest import NOW, release


def test_verified_diff_no_mutation_and_receipt(root, secret, trusted, policy):
    """Actual Ed25519 trust plus installed-byte validation precedes exact added/removed/changed file inventory."""
    initialize(root)
    first = release(secret)
    one = activate(root, first, trusted, policy, None)
    second = build(
        {"payload/new.txt": b"fictional readme"},
        secret,
        product=policy.product,
        target=policy.target,
        version="2.0.0",
        sequence=2,
        created=NOW - 1,
        expires=NOW + 100,
        revision="b" * 40,
    )
    before = {
        str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }
    result = review(
        root, second, trusted, policy, one["current"], "reviewer-1", "media-review-42"
    )
    assert {r["path"]: r["change"] for r in result["files"]} == {
        "inventory.spdx.json": "CHANGED",
        "payload/app.py": "REMOVED",
        "payload/new.txt": "ADDED",
    }
    assert (
        result["normal_activation_eligible_at_review"]
        and result["highest_sequence"] == 1
    )
    receipt = result.pop("receipt")
    assert receipt["review_sha256"] == sha(canonical(result))
    result["receipt"] = receipt
    assert before == {
        str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }
    assert "fictional readme" not in json.dumps(result)
    assert (
        review(
            root,
            first,
            trusted,
            policy,
            one["current"],
            "reviewer-1",
            "media-review-42",
        )["normal_activation_eligible_at_review"]
        is False
    )


def test_first_release_high_water_and_auth_failures(root, secret, trusted, policy):
    """Empty active state is explicit; rollback never lowers normal-activation eligibility floor."""
    initialize(root)
    first, second = release(secret, 1), release(secret, 2)
    initial = review(root, first, trusted, policy, None, "operator", "medium")
    assert initial["active_digest"] is None and all(
        r["change"] == "ADDED" for r in initial["files"]
    )
    one = activate(root, first, trusted, policy, None)
    two = activate(root, second, trusted, policy, one["current"])
    rollback(root, one["current"], two["current"], trusted, policy)
    assert not review(
        root, second, trusted, policy, one["current"], "operator", "medium"
    )["normal_activation_eligible_at_review"]
    assert state(root)["highest_sequence"] == 2
    with pytest.raises(Rejected):
        review(
            root,
            release(secret, 3),
            trusted,
            policy,
            two["current"],
            "operator",
            "medium",
        )
    wrong = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(Rejected):
        review(
            root,
            release(secret, 3),
            wrong,
            policy,
            one["current"],
            "operator",
            "medium",
        )
    (root / "releases" / one["current"] / "payload/app.py").write_bytes(
        b"tampered installed data"
    )
    with pytest.raises(Rejected):
        review(
            root,
            release(secret, 3),
            trusted,
            policy,
            one["current"],
            "operator",
            "medium",
        )


def test_cli_safe_output_and_aliases(root, secret, trusted, policy, tmp_path: Path):
    """Real command does no activation; existing output/invalid aliases/signatures cannot yield receipts."""
    initialize(root)
    archive = tmp_path / "release.zip"
    archive.write_bytes(release(secret))
    key = tmp_path / "trust.pub"
    key.write_bytes(trusted)
    out = tmp_path / "review"
    args = [
        "review",
        "--root",
        str(root),
        "--bundle",
        str(archive),
        "--trusted-key",
        str(key),
        "--product",
        policy.product,
        "--target",
        policy.target,
        "--now",
        str(NOW),
        "--expected",
        "none",
        "--operator",
        "operator",
        "--medium-reference",
        "medium",
        "--out",
        str(out),
    ]
    assert main(args) == 0 and state(root)["current"] is None
    original = (out / "review.json").read_bytes()
    assert main(args) == 2 and (out / "review.json").read_bytes() == original
    for operator in ("", "x" * 500, "<script>"):
        with pytest.raises(Rejected):
            review(
                root, archive.read_bytes(), trusted, policy, None, operator, "medium"
            )
    result = json.loads(original)
    result["scope"] = "<script>bad</script>"
    publish(result, tmp_path / "escaped")
    assert "&lt;script&gt;" in (tmp_path / "escaped/review.html").read_text(
        encoding="utf-8"
    )
