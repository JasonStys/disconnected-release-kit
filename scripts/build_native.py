"""Build the complete real offline workbench as one Windows portable executable. Jason Stys.

No publication, installation, shortcut change, host collection or Docker action.
"""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 41
# definition: main — line 45
# variable: version — line 58
# variable: source — line 61
# variable: dirty — line 64
# variable: output — line 69
# variable: release — line 69
# variable: extra_terms — line 83
# variable: terms_receipt — line 83
# variable: resource_paths — line 91
# variable: name — line 103
# variable: metadata — line 105
# variable: name — line 113
# variable: path — line 113
# variable: command — line 119
# variable: name — line 140
# variable: path — line 140
# variable: command — line 143
# variable: command — line 144
# variable: executable — line 158
# variable: stream — line 159
# variable: digest — line 160
# END CODE MAP

import hashlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

from native_common import icon, notices
from runtime_terms import collect

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> None:
    """Freeze exact allowlisted public resources and bind actual source/dirty state without publishing."""
    if sys.platform != "win32" or sys.version_info[:3] != (3, 14, 10):
        raise RuntimeError(
            "This portable recipe requires patched Windows CPython3.14.10"
        )
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.bindings import _rust

    from drkit import desktop_project as project
    from drkit.desktop_io import read_bytes

    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    if version != project.VERSION:
        raise ValueError("Native version coherence failed")
    source = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    dirty = bool(
        subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip()
    )
    release, output = ROOT / "release", ROOT / "out"
    release.mkdir(exist_ok=True)
    output.mkdir(exist_ok=True)
    if (
        cryptography.__version__ != "50.0.2"
        or backend.openssl_version_text() != "OpenSSL 4.0.3 29 Sep 2026"
    ):
        raise ValueError("Review actual crypto/OpenSSL runtime before packaging")
    notices(release / "notices.txt")
    (release / "notices.txt").write_bytes(
        (release / "notices.txt").read_bytes()
        + b"\n\nOpenSSL4.0.3 / OpenSSL project / Apache2.0\n"
        + (ROOT / "licenses/OpenSSL-4.0.3-LICENSE.txt").read_bytes()
    )
    extra_terms, terms_receipt = collect(ROOT / "licenses")
    (release / "notices.txt").write_bytes(
        (release / "notices.txt").read_bytes() + extra_terms
    )
    (output / "crypto-notice-receipt.json").write_text(
        json.dumps(terms_receipt, indent=2) + "\n", encoding="utf8"
    )
    icon(output / "app.ico")
    resource_paths = {
        name: (
            release / name
            if name == "notices.txt"
            else output / name
            if name == "app.ico"
            else Path(sys.base_prefix) / name
            if name == "python314.dll"
            else Path(_rust.__file__)
            if name == "cryptography/hazmat/bindings/_rust.pyd"
            else ROOT / name
        )
        for name in project.RESOURCES
    }
    metadata = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": version,
        "source": source,
        "source_dirty": dirty,
        "resources": {
            name: hashlib.sha256(read_bytes(path, 32 * 1024 * 1024)).hexdigest()
            for name, path in resource_paths.items()
        },
    }
    (release / "native-release.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf8"
    )
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--icon",
        str(output / "app.ico"),
        "--name",
        "DisconnectedReleaseKit",
        "--distpath",
        "release/portable",
        "--workpath",
        "out/native-build",
        "--specpath",
        "out",
        "--paths",
        str(ROOT),
    ]
    for name, path in resource_paths.items():
        if name in ("python314.dll", "cryptography/hazmat/bindings/_rust.pyd"):
            continue  # PyInstaller collects the actual interpreter DLL as a binary, not duplicate data.
        command += ["--add-data", str(path) + os.pathsep + Path(name).parent.as_posix()]
    command += [
        "--add-data",
        str(release / "native-release.json") + os.pathsep + ".",
        "scripts/native_entry.py",
    ]
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        env={
            **os.environ,
            "PYINSTALLER_CONFIG_DIR": str(output / "native-freezer-cache"),
        },
    )
    executable = release / "portable/DisconnectedReleaseKit.exe"
    with executable.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    executable.with_name(executable.name + ".sha256").write_text(
        digest + "  " + executable.name + "\n", encoding="ascii"
    )
    print(
        "Portable candidate built; source_dirty="
        + str(dirty)
        + "; not published or installed"
    )


if __name__ == "__main__":
    main()
