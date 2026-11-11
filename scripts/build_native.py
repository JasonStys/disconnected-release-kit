"""Build the complete real offline workbench as one Windows portable executable. Jason Stys.

No publication, installation, shortcut change, host collection or Docker action.
"""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 38
# definition: main — line 42
# variable: version — line 55
# variable: source — line 58
# variable: dirty — line 61
# variable: output — line 66
# variable: release — line 66
# variable: resource_paths — line 81
# variable: name — line 93
# variable: metadata — line 95
# variable: name — line 103
# variable: path — line 103
# variable: command — line 109
# variable: name — line 130
# variable: path — line 130
# variable: command — line 133
# variable: command — line 134
# variable: executable — line 148
# variable: stream — line 149
# variable: digest — line 150
# END CODE MAP

import hashlib
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

from native_common import icon, notices

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
