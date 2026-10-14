"""Jason Stys: actual no-uplink Linux namespace install of separately verified hash-locked wheelhouse."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 49
# definition: command — line 52
# parameter: argv — line 53
# parameter: cwd — line 53
# variable: environment — line 56
# variable: key — line 58
# variable: value — line 58
# definition: main — line 74
# variable: parser — line 76
# variable: args — line 78
# variable: actual — line 86
# variable: expected — line 87
# variable: links — line 90
# variable: routes — line 91
# variable: routes6 — line 92
# variable: entry — line 95
# variable: probe — line 97
# variable: egress_blocked — line 102
# variable: output — line 105
# variable: settings — line 106
# variable: policy — line 107
# variable: deployment — line 108
# variable: current — line 110
# variable: release — line 117
# variable: payload — line 118
# variable: environment — line 119
# variable: python — line 121
# variable: result — line 138
# variable: health — line 155
# variable: report — line 164
# END CODE MAP

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

from drkit.bundle import read_file
from drkit.contracts import MAX_BUNDLE, Policy, sha
from drkit.deploy import activate, initialize

ROOT = Path(__file__).resolve().parents[1]


def command(
    argv: list[str], *, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Execute a fixed authored test command with disabled pip configuration and a bounded timeout."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if "proxy" not in key.lower() and not key.startswith("PIP_")
    }
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return subprocess.run(
        argv,
        cwd=cwd,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )


def main() -> None:
    """Prove namespace identity/only-loopback first; install from trusted verified snapshot without indexes."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--namespace", required=True)
    args = parser.parse_args()
    if (
        sys.platform != "linux"
        or os.geteuid() != 0
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or not re.fullmatch(r"drk-[0-9]+", args.namespace)
    ):
        raise RuntimeError("offline namespace test is CI-only and explicitly guarded")
    actual = os.stat("/proc/self/ns/net")
    expected = os.stat("/run/netns/" + args.namespace)
    if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
        raise RuntimeError("owned namespace identity mismatch")
    links = json.loads(command(["ip", "-j", "link", "show"]).stdout)
    routes = json.loads(command(["ip", "-j", "route", "show", "table", "main"]).stdout)
    routes6 = json.loads(
        command(["ip", "-j", "-6", "route", "show", "table", "main"]).stdout
    )
    if [entry["ifname"] for entry in links] != ["lo"] or routes or routes6:
        raise RuntimeError("namespace unexpectedly has an uplink or route")
    with socket.socket() as probe:
        probe.settimeout(1)
        try:
            probe.connect(("198.51.100.1", 9))
        except OSError:
            egress_blocked = True
        else:
            raise AssertionError("no-route egress unexpectedly succeeded")
    output = ROOT / "out/offline"
    settings = json.loads((output / "settings.json").read_text(encoding="utf-8"))
    policy = Policy("demo-service", settings["target"], int(time.time()))
    deployment = output / "deployment"
    initialize(deployment)
    current = activate(
        deployment,
        read_file(output / "bundle.zip", MAX_BUNDLE),
        read_file(output / "trust.pub", 32),
        policy,
        None,
    )
    release = deployment / "releases" / current["current"]
    payload = release / "payload"
    environment = output / "venv"
    command([sys.executable, "-m", "venv", str(environment)])
    python = str(environment / "bin/python")
    command(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--only-binary=:all:",
            "--find-links",
            str(payload / "wheels"),
            "--require-hashes",
            "-r",
            str(payload / "requirements.lock"),
        ]
    )
    command([python, "-m", "pip", "check"])
    result = command(
        [
            python,
            "-m",
            "drkit.cli",
            "verify",
            "--bundle",
            str(release / "bundle.zip"),
            "--trusted-key",
            str(output / "trust.pub"),
            "--product",
            "demo-service",
            "--target",
            settings["target"],
        ],
        cwd=payload,
    )
    health = json.loads(
        command([python, str(payload / "service.py")], cwd=payload).stdout
    )
    assert health == {
        "status": "ready",
        "product": "demo-service",
        "author": "Jason Stys",
    }
    assert json.loads(result.stdout)["sha256"] == current["current"]
    report = dict(
        author="Jason Stys",
        scope="actual no-uplink namespace offline wheel installation",
        python=sys.version.split()[0],
        source_revision=settings["source_revision"],
        interfaces=["lo"],
        ipv4_main_routes=0,
        ipv6_main_routes=0,
        reserved_address_connect_blocked=egress_blocked,
        pip_no_index=True,
        pip_require_hashes=True,
        pip_check_passed=True,
        installed_wheels=len(list((payload / "wheels").glob("*.whl"))),
        signed_bundle_reverified_in_new_environment=True,
        trusted_demo_app_health=health["status"],
        bundle_sha256=current["current"],
        requirements_sha256=sha((payload / "requirements.lock").read_bytes()),
    )
    (output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
