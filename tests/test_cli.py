"""Jason Stys: complete explicit CLI lifecycle, safe failures and standalone module entry point."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: test_cli_lifecycle — line 38
# parameter: capsys — line 38
# parameter: tmp_path — line 38
# variable: keys — line 40
# variable: staging — line 40
# variable: root — line 45
# variable: common — line 48
# variable: digests — line 58
# variable: sequence — line 59
# variable: bundle — line 60
# variable: record — line 91
# definition: test_real_clock_and_entry — line 136
# parameter: archive — line 137
# parameter: capsys — line 137
# parameter: tmp_path — line 137
# parameter: trusted — line 137
# variable: bundle — line 140
# variable: key — line 140
# variable: argv — line 143
# variable: outcome — line 162
# definition: test_parser_rejects — line 167
# END CODE MAP

import json
import runpy
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from conftest import NOW

from drkit.cli import main


def test_cli_lifecycle(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Use the real CLI to create demo trust, build, verify, activate, rollback and report."""
    keys, staging = tmp_path / "keys", tmp_path / "source"
    staging.mkdir()
    (staging / "app.py").write_text("print('demo')", encoding="utf-8")
    assert main(["demo-keygen", "--out", str(keys)]) == 0
    capsys.readouterr()
    root = tmp_path / "deploy"
    assert main(["init", "--root", str(root)]) == 0
    capsys.readouterr()
    common = [
        "--trusted-key",
        str(keys / "trust.pub"),
        "--product",
        "demo-service",
        "--target",
        "portable-source",
        "--now",
        str(NOW),
    ]
    digests = []
    for sequence in (1, 2):
        bundle = tmp_path / f"v{sequence}.zip"
        assert (
            main(
                [
                    "build",
                    "--source",
                    str(staging),
                    "--private-key",
                    str(keys / "demo.key"),
                    "--out",
                    str(bundle),
                    "--version",
                    f"1.0.{sequence}",
                    "--sequence",
                    str(sequence),
                    "--product",
                    "demo-service",
                    "--target",
                    "portable-source",
                    "--created",
                    str(NOW - 1),
                    "--expires",
                    str(NOW + 3600),
                    "--revision",
                    "a" * 40,
                ]
            )
            == 0
        )
        capsys.readouterr()
        assert main(["verify", "--bundle", str(bundle), *common]) == 0
        record = json.loads(capsys.readouterr().out)
        digests.append(record["sha256"])
        assert (
            main(
                [
                    "activate",
                    "--bundle",
                    str(bundle),
                    "--root",
                    str(root),
                    "--expected",
                    "none" if sequence == 1 else digests[0],
                    *common,
                ]
            )
            == 0
        )
        capsys.readouterr()
    assert (
        main(
            [
                "rollback",
                "--root",
                str(root),
                "--expected",
                digests[1],
                "--release",
                digests[0],
                *common,
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["status", "--root", str(root)]) == 0
    assert json.loads(capsys.readouterr().out)["highest_sequence"] == 2
    assert main(["demo-keygen", "--out", str(keys)]) == 2
    assert (
        json.loads(capsys.readouterr().out)["error"]
        == "local filesystem operation failed"
    )
    assert main(["verify", "--bundle", str(bundle), *common, "--product", "wrong"]) == 2
    assert "product/target mismatch" in capsys.readouterr().out


def test_real_clock_and_entry(
    tmp_path: Path, archive: bytes, trusted: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    """Operational clock defaults to real time; module execution forwards the controlled return code."""
    key, bundle = tmp_path / "trust.pub", tmp_path / "release.zip"
    key.write_bytes(trusted)
    bundle.write_bytes(archive)
    argv = [
        "verify",
        "--bundle",
        str(bundle),
        "--trusted-key",
        str(key),
        "--product",
        "demo-service",
        "--target",
        "portable-source",
    ]
    with patch("drkit.cli.time.time", return_value=NOW):
        assert main(argv) == 0
    capsys.readouterr()
    with patch.dict(sys.modules):
        sys.modules.pop("drkit.cli", None)
        with patch.object(
            sys, "argv", ["drkit", "status", "--root", str(tmp_path / "missing")]
        ):
            with pytest.raises(SystemExit) as outcome:
                runpy.run_module("drkit.cli", run_name="__main__")
    assert outcome.value.code == 2


def test_parser_rejects() -> None:
    """Invalid or absent operations produce argparse usage errors before any mutation."""
    with pytest.raises(SystemExit):
        main([])
