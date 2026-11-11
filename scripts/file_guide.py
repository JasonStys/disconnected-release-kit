"""Jason Stys: exact tracked-file README purpose inventory, unknown files fail rather than receive guesses."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 35
# variable: BEGIN — line 36
# variable: END — line 36
# variable: SPECIAL — line 37
# definition: purpose — line 63
# parameter: name — line 63
# variable: text — line 67
# variable: lines — line 72
# variable: index — line 73
# variable: line — line 73
# variable: description — line 75
# variable: continuation — line 77
# variable: description — line 83
# definition: main — line 88
# variable: parser — line 90
# variable: args — line 92
# variable: names — line 93
# variable: rows — line 101
# variable: name — line 102
# variable: label — line 103
# variable: path — line 105
# variable: original — line 106
# variable: end — line 107
# variable: start — line 107
# variable: expected — line 108
# END CODE MAP

import argparse
import ast
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BEGIN, END = "<!-- BEGIN FILE GUIDE -->", "<!-- END FILE GUIDE -->"
SPECIAL = {
    "docs/reports/windows-application-guide-1.1.0.docx": "Current peer-reviewed installed app guide with actual screenshots and immutable code.",
    "docs/reports/windows-application-guide-1.1.0.json": "Exact guide, source, image and individually reviewed page identities.",
    "docs/reports/installed-windows-1.1.0-2026-11-11.md": "Observed installed workflows, delivery evidence, data preservation and practical limits.",
    "licenses/cryptography-50.0.2-rust-notices.txt": "Exact32crate/62original notice texts from checksum-verified registry archives, conservative provider-SBOM scope.",
    "licenses/cryptography-50.0.2-rust-inventory.json": "Minimal exact-wheel Rust component, archive and original-notice byte identities; provider private build paths omitted.",
    "licenses/RUST-COPYRIGHT-library.html": "Actual Rust1.98.1 standard-library copyright inventory matching the compiler-source identity embedded in the crypto wheel.",
    "requirements-native.lock": "Exact hash-locked portable freezer graph, separate from the project runtime.",
    "licenses/OpenSSL-4.0.3-LICENSE.txt": "Unmodified Apache-2.0 license from the exact OpenSSL 4.0.3 source tag used by the cryptography wheel.",
    "docs/reports/project-guide.docx": "Reviewed source-bound Word guide with dated validation observations and practical limits.",
    "docs/reports/publications.json": "Exact publication hashes, reviewed page identities and source/evidence baselines.",
    ".gitignore": "Exclude local keys, environments, release bundles and private diagnostics.",
    ".gitattributes": "Consistent LF text checkouts across operating systems.",
    "LICENSE": "MIT license for Jason Stys's authored code.",
    "requirements.lock": "Universal full hash-locked offline runtime graph.",
    "requirements-dev.lock": "Universal full hash-locked development and independent audit graph.",
    "tools.lock.json": "Official Linux scanner versions, URLs and SHA256 digests.",
    "vendor/spdx-schema.json": "Immutable upstream SPDX 2.3.1 JSON schema; third-party CC-BY-3.0.",
    "vendor/SPDX-LICENSE.txt": "Unmodified upstream CC-BY-3.0 license for the vendored SPDX schema.",
    "docs/reports/ci.json": "Actual immutable accepted-source CI snapshot, not a future guarantee.",
    "docs/reports/demo.json": "Actual synthetic signed-release/tamper/rollback regression evidence.",
    "docs/reports/offline.json": "Actual no-uplink Linux namespace wheelhouse installation evidence.",
    "docs/reports/benchmark.json": "Measured bounded build/verification timing and Python allocation peak.",
}


def purpose(name: str) -> str:
    """Read the authored module/header/title purpose or explicit noncommentable-file description."""
    if name in SPECIAL:
        return SPECIAL[name]
    text = (ROOT / name).read_text(encoding="utf-8")
    if name.endswith(".py"):
        return (ast.get_docstring(ast.parse(text)) or "").splitlines()[0]
    if name.endswith(".md"):
        return text.splitlines()[0].lstrip("# ") + "."
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if "Jason Stys:" in line:
            description = line.lstrip("#!/- ")
            if name.endswith((".cpp", ".hpp", ".rs")):
                for continuation in lines[index + 1 :]:
                    if (
                        not continuation.startswith("//")
                        or "BEGIN CODE MAP" in continuation
                    ):
                        break
                    description += " " + continuation.lstrip("/! ")
            return description
    raise ValueError("Tracked-file purpose missing: " + name)


def main() -> None:
    """Generate/check an exact full tracked-file table after staging only reviewed nonprivate files."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    names = (
        subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
        .decode()
        .rstrip("\0")
        .split("\0")
    )
    if names == [""]:
        raise ValueError("Stage reviewed files first")
    rows = ["| File | Purpose |", "| --- | --- |"]
    for name in sorted(names):
        label = name.replace("_", "\\_")
        rows.append(f"| [{label}]({name}) | {purpose(name).replace('|', '/')} |")
    path = ROOT / "README.md"
    original = path.read_text(encoding="utf-8")
    start, end = original.index(BEGIN) + len(BEGIN), original.index(END)
    expected = original[:start] + "\n\n" + "\n".join(rows) + "\n\n" + original[end:]
    if args.check and expected != original:
        raise ValueError("README file guide stale")
    if not args.check:
        path.write_text(expected, encoding="utf-8", newline="\n")
    print(f"README complete inventory: {len(names)}")


if __name__ == "__main__":
    main()
