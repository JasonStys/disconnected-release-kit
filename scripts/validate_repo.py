"""Jason Stys: fail-closed tracked-file privacy, third-party schema integrity and no-storage workflow checks."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 26
# variable: SCHEMA_SHA256 — line 27
# definition: main — line 30
# variable: names — line 32
# variable: name — line 38
# variable: parts — line 39
# variable: part — line 41
# variable: path — line 44
# variable: text — line 47
# variable: schema — line 55
# variable: path — line 58
# variable: text — line 59
# variable: action — line 66
# variable: codeql — line 71
# variable: flag — line 72
# END CODE MAP

import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_SHA256 = "4126dc29f15e92feec92e9622f4939131ad58b125d6f578aa93e980a6e6f3212"


def main() -> None:
    """Check reviewed tracked files only; this guard complements, never replaces, secret/security review."""
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    for name in names:
        parts = name.split("/")
        if any(
            part in {"out", ".venv", ".tools", "__pycache__"} for part in parts
        ) or name.lower().endswith((".key", ".pem", ".zip", ".whl", ".env")):
            raise ValueError("private/build file was tracked")
        path = ROOT / name
        if path.is_symlink() or path.is_junction():
            raise ValueError("tracked links are forbidden")
        text = path.read_text(encoding="utf-8")
        if re.search(
            r"(?:ghp_|github_pat_|sk-proj-)[A-Za-z0-9_]{12,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            text,
        ):
            raise ValueError("possible credential in tracked text")
        if name.endswith(".json"):
            json.loads(text)
    schema = ROOT / "vendor/spdx-schema.json"
    if hashlib.sha256(schema.read_bytes()).hexdigest() != SCHEMA_SHA256:
        raise ValueError("vendored upstream schema changed")
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        text = path.read_text(encoding="utf-8")
        if (
            "upload-artifact@" in text
            or "actions/cache@" in text
            or re.search(r"^\s+cache:", text, re.M)
        ):
            raise ValueError("Actions artifact/cache storage is disabled for this lab")
        for action in re.findall(r"uses:\s*([^\s#]+)", text):
            if not re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", action):
                raise ValueError(
                    "every remote action must be pinned to a reviewed commit"
                )
    codeql = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
    for flag in ("trap-caching", "dependency-caching", "upload-database"):
        if flag + ": false" not in codeql:
            raise ValueError("CodeQL cache/database opt-out missing")
    print(
        f"Privacy, workflow storage and schema guards passed: {len(names)} tracked files"
    )


if __name__ == "__main__":
    main()
