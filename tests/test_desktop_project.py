"""Actual independent signatures, transfer/CAS/floor and nonmutation GUI oracles. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: execute — line 88
# parameter: parameters — line 88
# parameter: tmp_path — line 88
# variable: stage — line 90
# definition: test_actual_prepared_signatures_changes_and_nonreset_floor — line 108
# parameter: active_sequence — line 109
# parameter: eligible — line 109
# parameter: high_water — line 109
# parameter: index — line 109
# parameter: sequence — line 109
# parameter: tmp_path — line 109
# variable: files — line 112
# variable: value — line 113
# variable: payloads — line 120
# variable: row — line 122
# variable: expected — line 125
# variable: rows — line 138
# variable: row — line 139
# definition: operational — line 144
# parameter: tmp_path — line 144
# variable: key — line 146
# variable: public — line 147
# variable: initial — line 149
# variable: candidate — line 160
# variable: archive — line 171
# variable: parameters — line 173
# variable: root — line 184
# variable: active — line 186
# definition: test_actual_selected_verification_does_not_assert_activation_or_export_secrets — line 192
# parameter: operational — line 193
# parameter: tmp_path — line 193
# variable: _active — line 196
# variable: archive — line 196
# variable: parameters — line 196
# variable: public — line 196
# variable: root — line 196
# variable: before — line 197
# variable: files — line 198
# variable: value — line 199
# variable: row — line 201
# variable: raw — line 205
# definition: test_selected_deployment_cas_review_preserves_every_original_byte — line 212
# parameter: operational — line 213
# parameter: tmp_path — line 213
# variable: _archive — line 216
# variable: _public — line 216
# variable: active — line 216
# variable: parameters — line 216
# variable: root — line 216
# variable: before — line 220
# variable: p — line 222
# variable: files — line 225
# variable: after — line 229
# variable: p — line 231
# definition: test_real_selected_bad_trust_bytes_expiry_and_cas_cannot_be_certified — line 250
# parameter: fault — line 251
# parameter: operational — line 251
# parameter: tmp_path — line 251
# variable: active — line 254
# variable: archive — line 254
# variable: parameters — line 254
# variable: public — line 254
# variable: root — line 254
# variable: raw — line 261
# variable: before — line 278
# definition: test_invalid_settings_never_become_a_default_or_command — line 299
# parameter: field — line 299
# parameter: tmp_path — line 299
# parameter: value — line 299
# variable: parameters — line 301
# definition: test_blank_clock_uses_actual_time_and_unknown_prepared_refuses — line 307
# parameter: monkeypatch — line 307
# variable: parameters — line 309
# END CODE MAP

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drkit import desktop_project as project
from drkit.bundle import build
from drkit.contracts import Rejected as CoreRejected
from drkit.deploy import activate, initialize
from drkit.desktop_io import Rejected, json_value


def execute(tmp_path, parameters):
    """Use actual cryptography and core review in one fresh owned stage, never normal profiles/deployments."""
    stage = tmp_path / "stage"
    stage.mkdir()
    return project.analyze(None, parameters, stage)[2]


@pytest.mark.parametrize(
    "index,sequence,eligible,active_sequence,high_water",
    [
        (0, 1, True, None, 0),
        (1, 2, True, 1, 1),
        (2, 2, True, 1, 1),
        (3, 2, True, 1, 1),
        (4, 2, False, 2, 2),
        (5, 2, False, 1, 2),
        (6, 3, True, 1, 1),
        (7, 2, True, None, 0),
    ],
)
def test_actual_prepared_signatures_changes_and_nonreset_floor(
    tmp_path, index, sequence, eligible, active_sequence, high_water
):
    """Real signatures/active byte reauthentication distinguish eligibility from verified-but-reused sequence."""
    files = execute(tmp_path, project.scenario(project.SCENARIOS[index]))
    value = json_value(files["review.json"])
    assert value["candidate_sequence"] == sequence
    assert (
        value["active_sequence"] == active_sequence
        and value["highest_sequence"] == high_water
    )
    assert value["normal_activation_eligible_at_review"] is eligible
    payloads = {
        row["path"]: row["change"]
        for row in value["files"]
        if row["path"].startswith("payload/")
    }
    expected = {
        0: {"payload/config.json": "ADDED", "payload/readme.txt": "ADDED"},
        1: {
            "payload/config.json": "CHANGED",
            "payload/readme.txt": "UNCHANGED",
            "payload/notes.txt": "ADDED",
        },
        2: {"payload/config.json": "CHANGED", "payload/readme.txt": "REMOVED"},
        3: {"payload/config.json": "UNCHANGED", "payload/readme.txt": "UNCHANGED"},
    }
    if index in expected:
        assert payloads == expected[index]
    assert "not a digital signature" in value["receipt"]["claims"]
    for rows in project.views(files).values():
        for row in rows:
            assert len(project.cells(row)) == 4


@pytest.fixture
def operational(tmp_path):
    """Independent caller key and actual owned root, disjoint from GUI prepared fixtures and package resources."""
    key = Ed25519PrivateKey.generate()
    public = tmp_path / "trusted-public.bin"
    public.write_bytes(key.public_key().public_bytes_raw())
    initial = build(
        {"payload/one.txt": b"PRIVATE-PAYLOAD-NOT-EXPORTED"},
        key.private_bytes_raw(),
        product="research-data",
        version="1.0.0",
        sequence=1,
        target="portable-data",
        created=1893456000,
        expires=1893459600,
        revision="b" * 40,
    )
    candidate = build(
        {"payload/two.txt": b"second private contents"},
        key.private_bytes_raw(),
        product="research-data",
        version="1.1.0",
        sequence=2,
        target="portable-data",
        created=1893456000,
        expires=1893459600,
        revision="c" * 40,
    )
    archive = tmp_path / "authorized.zip"
    archive.write_bytes(candidate)
    parameters = project.scenario(project.SCENARIOS[0])
    parameters.update(
        mode=project.MODES[1],
        bundle=str(archive),
        trusted_key=str(public),
        product="research-data",
        target="portable-data",
        expected="none",
        operator="reviewer-alias",
        medium="transfer-alias",
    )
    root = tmp_path / "existing-deployment"
    initialize(root)
    active = activate(
        root, initial, public.read_bytes(), project.policy(parameters), None
    )
    return parameters, root, active, archive, public


def test_actual_selected_verification_does_not_assert_activation_or_export_secrets(
    tmp_path, operational
):
    """Caller-supplied signature is authenticated against a separately selected public key, never embedded trust."""
    parameters, root, _active, archive, public = operational
    before = (root / "state.json").read_bytes()
    files = execute(tmp_path, parameters)
    value = json_value(files["review.json"])
    assert value["candidate_sequence"] == 2
    assert all(row["change"] == "VERIFIED_ONLY" for row in value["files"])
    assert "normal_activation_eligible_at_review" not in value
    assert project.views(files)["Changed payload files"] == []
    assert (root / "state.json").read_bytes() == before
    for raw in files.values():
        assert b"PRIVATE-PAYLOAD-NOT-EXPORTED" not in raw
        assert b"second private contents" not in raw
        assert str(tmp_path).encode() not in raw
        assert archive.read_bytes() not in raw and public.read_bytes() not in raw


def test_selected_deployment_cas_review_preserves_every_original_byte(
    tmp_path, operational
):
    """Real candidate/active signatures, files and exact current expectation precede a nonmutating transfer review."""
    parameters, root, active, _archive, _public = operational
    parameters.update(
        mode=project.MODES[2], deployment=str(root), expected=active["current"]
    )
    before = {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }
    files = execute(tmp_path, parameters)
    assert (
        json_value(files["review.json"])["normal_activation_eligible_at_review"] is True
    )
    after = {
        p.relative_to(root).as_posix(): p.read_bytes()
        for p in root.rglob("*")
        if p.is_file()
    }
    assert before == after


@pytest.mark.parametrize(
    "fault",
    [
        "wrong-key",
        "tamper",
        "expired",
        "wrong-target",
        "stale-cas",
        "active-tamper",
        "floor",
        "invalid-digest",
    ],
)
def test_real_selected_bad_trust_bytes_expiry_and_cas_cannot_be_certified(
    tmp_path, operational, fault
):
    """Independent cryptographic/state negatives use real packages rather than a mocked success/failure flag."""
    parameters, root, active, archive, public = operational
    parameters.update(
        mode=project.MODES[2], deployment=str(root), expected=active["current"]
    )
    if fault == "wrong-key":
        public.write_bytes(Ed25519PrivateKey.generate().public_key().public_bytes_raw())
    elif fault == "tamper":
        raw = bytearray(archive.read_bytes())
        raw[len(raw) // 2] ^= 1
        archive.write_bytes(raw)
    elif fault == "expired":
        parameters["as_of"] = "2030-01-01T01:00:00Z"
    elif fault == "wrong-target":
        parameters["target"] = "different-target"
    elif fault == "stale-cas":
        parameters["expected"] = "f" * 64
    elif fault == "active-tamper":
        (root / "releases" / active["current"] / "payload/one.txt").write_bytes(
            b"changed owned fixture"
        )
    elif fault == "floor":
        parameters["minimum_sequence"] = "3"
    else:
        parameters["expected"] = "../other"
    before = (root / "state.json").read_bytes()
    with pytest.raises((CoreRejected, Rejected, ValueError)):
        execute(tmp_path, parameters)
    assert (root / "state.json").read_bytes() == before
    assert not (root / ".operation.lock").exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("mode", "execute-payload"),
        ("as_of", "2030-02-30T00:00:00Z"),
        ("as_of", "2030-1-01T00:00:00Z"),
        ("as_of", "2030-01-01T00:00:00+00:00"),
        ("minimum_sequence", "-1"),
        ("minimum_sequence", "NaN"),
        ("minimum_sequence", "2147483648"),
        ("operator", "private actor with spaces"),
        ("transfer_case", "foreign"),
    ],
)
def test_invalid_settings_never_become_a_default_or_command(tmp_path, field, value):
    """Malformed trust clock/alias/operation refuses; the selected device/deployment is never initialized by the GUI."""
    parameters = project.scenario(project.SCENARIOS[0])
    parameters[field] = value
    with pytest.raises((CoreRejected, Rejected, ValueError)):
        execute(tmp_path, parameters)


def test_blank_clock_uses_actual_time_and_unknown_prepared_refuses(monkeypatch):
    """Operational current time is sampled explicitly; a malformed or missing fixture does not silently bypass expiry."""
    parameters = project.scenario(project.SCENARIOS[0])
    parameters["as_of"] = ""
    monkeypatch.setattr(project.time, "time", lambda: 1893456355)
    assert project.policy(parameters).now == 1893456355
    with pytest.raises(Rejected):
        project.scenario("unknown")
