"""Actual final portable widgets/core/native-window acceptance with independent oracles. Jason Stys."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: capture — line 135
# parameter: target — line 135
# parameter: window — line 135
# variable: load — line 141
# variable: gdi — line 142
# variable: user — line 142
# variable: pointer — line 143
# variable: arguments — line 144
# variable: library — line 144
# variable: name — line 144
# variable: result — line 144
# variable: function — line 170
# attribute: argtypes — line 171
# attribute: restype — line 171
# variable: handle — line 174
# variable: rectangle — line 175
# variable: height — line 178
# variable: width — line 178
# variable: source — line 181
# variable: destination — line 182
# variable: bitmap — line 183
# variable: previous — line 184
# variable: pixels — line 189
# variable: header — line 190
# variable: raw — line 208
# variable: scanlines — line 209
# variable: row — line 210
# variable: column — line 212
# variable: offset — line 213
# definition: chunk — line 216
# parameter: data — line 216
# parameter: name — line 216
# definition: oracle — line 238
# parameter: files — line 238
# parameter: index — line 238
# variable: value — line 240
# variable: row — line 253
# variable: row — line 262
# variable: expected — line 266
# variable: raw — line 287
# definition: exercise — line 290
# parameter: output — line 290
# parameter: reopen — line 290
# parameter: window — line 290
# variable: expected — line 300
# variable: started — line 300
# variable: receipt — line 301
# variable: deadline — line 320
# definition: progress — line 322
# parameter: stage — line 322
# definition: finish — line 329
# parameter: failed — line 329
# attribute: acceptance_result — line 331
# variable: name — line 339
# variable: raw — line 339
# variable: row — line 341
# definition: checked — line 346
# parameter: callback — line 346
# variable: trace — line 354
# variable: trace — line 362
# definition: callback_failed — line 365
# parameter: _traceback — line 366
# parameter: _value — line 366
# parameter: kind — line 366
# definition: wait — line 372
# parameter: callback — line 372
# definition: layout — line 382
# variable: widgets — line 387
# variable: name — line 388
# variable: widget — line 390
# definition: rejected — line 412
# definition: licenses — line 421
# variable: dialogs — line 424
# variable: child — line 426
# variable: dialog — line 430
# variable: pending — line 431
# variable: texts — line 432
# variable: widget — line 434
# variable: text — line 440
# variable: value — line 443
# definition: completed — line 458
# parameter: index — line 458
# variable: files — line 464
# variable: parent — line 491
# variable: target — line 497
# variable: path — line 498
# variable: selected — line 501
# definition: start — line 512
# parameter: index — line 512
# variable: key — line 527
# variable: archive — line 528
# variable: selected — line 539
# variable: public — line 540
# variable: key — line 562
# definition: package — line 564
# parameter: content — line 564
# parameter: sequence — line 564
# variable: candidate — line 578
# variable: initial — line 578
# variable: public — line 582
# variable: deployment — line 584
# variable: active — line 586
# variable: selected — line 593
# variable: field — line 599
# variable: path — line 599
# definition: begin — line 613
# variable: identity — line 617
# attribute: report_callback_exception — line 633
# END CODE MAP

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import tkinter as tk
import zlib
from pathlib import Path
from tkinter import ttk
from typing import TYPE_CHECKING, Any

from drkit import desktop_project as project
from drkit.desktop_io import json_value

if TYPE_CHECKING:
    from drkit.desktop import Workbench


def capture(window: Workbench, target: Path) -> None:
    """Capture only this owned synthetic Tk window via PrintWindow, never the user's whole desktop."""
    if sys.platform != "win32":
        raise OSError("native screenshot acceptance targets Windows")
    from ctypes import wintypes

    load = ctypes.WinDLL
    user, gdi = load("user32", use_last_error=True), load("gdi32", use_last_error=True)
    pointer = ctypes.c_void_p
    for library, name, arguments, result in [
        (user, "GetAncestor", [pointer, ctypes.c_uint], pointer),
        (user, "GetWindowDC", [pointer], pointer),
        (gdi, "CreateCompatibleDC", [pointer], pointer),
        (gdi, "CreateCompatibleBitmap", [pointer, ctypes.c_int, ctypes.c_int], pointer),
        (gdi, "SelectObject", [pointer, pointer], pointer),
        (gdi, "DeleteObject", [pointer], ctypes.c_int),
        (gdi, "DeleteDC", [pointer], ctypes.c_int),
        (user, "ReleaseDC", [pointer, pointer], ctypes.c_int),
        (user, "PrintWindow", [pointer, pointer, ctypes.c_uint], ctypes.c_int),
        (user, "GetWindowRect", [pointer, ctypes.POINTER(wintypes.RECT)], ctypes.c_int),
        (
            gdi,
            "GetDIBits",
            [
                pointer,
                pointer,
                ctypes.c_uint,
                ctypes.c_uint,
                pointer,
                pointer,
                ctypes.c_uint,
            ],
            ctypes.c_int,
        ),
    ]:
        function = getattr(library, name)
        function.argtypes, function.restype = arguments, result
    # Flush this owned native window's pending control messages before reading its pixels.
    window.root.update()
    handle = user.GetAncestor(window.root.winfo_id(), 2)
    rectangle = wintypes.RECT()
    if not user.GetWindowRect(handle, ctypes.byref(rectangle)):
        raise OSError("owned window bounds unavailable")
    width, height = rectangle.right - rectangle.left, rectangle.bottom - rectangle.top
    if not 1 <= width <= 4096 or not 1 <= height <= 4096:
        raise OSError("owned screenshot outside bounded dimensions")
    source = user.GetWindowDC(handle)
    destination = gdi.CreateCompatibleDC(source)
    bitmap = gdi.CreateCompatibleBitmap(source, width, height)
    previous = gdi.SelectObject(destination, bitmap)
    try:
        if not user.PrintWindow(handle, destination, 2):
            raise OSError("owned window rendering unavailable")
        gdi.SelectObject(destination, previous)
        pixels = ctypes.create_string_buffer(width * height * 4)
        header = ctypes.create_string_buffer(
            struct.pack(
                "<IiiHHIIiiII",
                40,
                width,
                -height,
                1,
                32,
                0,
                width * height * 4,
                0,
                0,
                0,
                0,
            )
        )
        if gdi.GetDIBits(source, bitmap, 0, height, pixels, header, 0) != height:
            raise OSError("owned screenshot pixels incomplete")
        raw = pixels.raw
        scanlines = bytearray()
        for row in range(height):
            scanlines.append(0)
            for column in range(width):
                offset = (row * width + column) * 4
                scanlines.extend((raw[offset + 2], raw[offset + 1], raw[offset]))

        def chunk(name: bytes, data: bytes) -> bytes:
            """Encode a bounded standard PNG chunk with its actual CRC."""
            return (
                struct.pack(">I", len(data))
                + name
                + data
                + struct.pack(">I", zlib.crc32(name + data))
            )

        target.write_bytes(
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(scanlines)))
            + chunk(b"IEND", b"")
        )
    finally:
        gdi.SelectObject(destination, previous)
        gdi.DeleteObject(bitmap)
        gdi.DeleteDC(destination)
        user.ReleaseDC(handle, source)


def oracle(index: int, files: dict[str, bytes]) -> None:
    """Require actual independent signatures, nonreset high-water marks and absence of operational activation claims."""
    value = json_value(files["review.json"])
    if index == 9:
        assert value["kind"] == "authenticated_transfer_review"
        assert (
            value["candidate_sequence"],
            value["active_sequence"],
            value["highest_sequence"],
            value["normal_activation_eligible_at_review"],
        ) == (2, 1, 1, True)
        assert value["receipt"]["operator_alias"] == "native-reviewer"
        assert value["receipt"]["medium_reference_alias"] == "native-transfer"
        assert {
            row["path"]: row["change"]
            for row in value["files"]
            if row["path"].startswith("payload/")
        } == {"payload/private.txt": "CHANGED"}
    elif index == 8:
        assert (
            value["kind"] == "authenticated_bundle_verification"
            and value["candidate_sequence"] == 1
        )
        assert len(value["files"]) == 2 and all(
            row["change"] == "VERIFIED_ONLY" for row in value["files"]
        )
        assert "normal_activation_eligible_at_review" not in value
    else:
        expected = (
            (1, True, None, 0),
            (2, True, 1, 1),
            (2, True, 1, 1),
            (2, True, 1, 1),
            (2, False, 2, 2),
            (2, False, 1, 2),
            (3, True, 1, 1),
            (2, True, None, 0),
        )
        assert (
            value["candidate_sequence"],
            value["normal_activation_eligible_at_review"],
            value["active_sequence"],
            value["highest_sequence"],
        ) == expected[index]
        assert value["receipt"]["event"] == "VERIFIED_NONEXECUTING_REVIEW"
    assert (
        "signing/activation/rollback are separate"
        in json_value(files["input-scope.json"])["scope"]
    )
    assert all(b"EXTERNAL-PRIVATE-CONTENT" not in raw for raw in files.values())


def exercise(window: Workbench, output: Path, reopen: bool) -> None:
    """Drive the same real offline widgets/core worker and retained-owner close; supply only OS file-picker selection."""
    from unittest.mock import patch

    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend

    assert cryptography.__version__ == "50.0.2"
    assert backend.openssl_version_text() == "OpenSSL 4.0.3 29 Sep 2026"
    output.mkdir(mode=0o700)
    started, expected = time.monotonic(), 10
    receipt: dict[str, Any] = {
        "schema": 1,
        "product": project.PRODUCT,
        "version": project.VERSION,
        "source": window.identity["source"],
        "source_dirty": window.identity["source_dirty"],
        "python_version": sys.version.split()[0],
        "python_dll_sha256": window.identity.get("python_dll_sha256"),
        "pid": os.getpid(),
        "parent_pid": os.getppid(),
        "synthetic": True,
        "cryptography_version": cryptography.__version__,
        "crypto_openssl_version": backend.openssl_version_text(),
        "reopen": reopen,
        "passed": False,
        "steps": [],
        "tcl_version": str(window.root.tk.call("info", "patchlevel")),
        "tk_version": str(window.root.tk.call("package", "require", "Tk")),
    }
    deadline = started + 65

    def progress(stage: str) -> None:
        """Keep value-free milestone evidence if a native service or UI step fails."""
        receipt["last_stage"] = stage
        (output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )

    def finish(failed: bool = False) -> None:
        """Request normal close and preserve exact bundle identities; failure is never replaced by success on cleanup."""
        window.acceptance_result = not failed
        receipt["passed"] = not failed
        if failed:
            receipt["safe_application_status"] = window.status.get()[:240]
        receipt["journey_elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
        receipt["bundles"] = {
            str(row["id"]): {
                name: hashlib.sha256(raw).hexdigest()
                for name, raw in window.state.files(row["id"]).items()
            }
            for row in window.state.history()
        }
        progress("failed-retained" if failed else "normal-close-requested")
        window.exit()

    def checked(callback: Any) -> None:
        """A failed assertion becomes a nonzero normal app exit, without private exception/body output."""
        try:
            callback()
        except Exception as error:
            receipt["failure_stage"] = callback.__name__
            receipt["failure_type"] = type(error).__name__[:60]
            receipt["failure_step"] = receipt.get("last_stage")
            trace = error.__traceback__
            while trace is not None:
                if (
                    Path(trace.tb_frame.f_code.co_filename).name
                    == "native_acceptance.py"
                ):
                    receipt["failure_function"] = trace.tb_frame.f_code.co_name[:60]
                    receipt["failure_line"] = trace.tb_lineno
                trace = trace.tb_next
            finish(True)

    def callback_failed(
        kind: type[BaseException], _value: BaseException, _traceback: Any
    ) -> None:
        """Do not lose Tk callback errors in a windowed executable without stderr."""
        receipt["failure_type"] = kind.__name__[:60]
        finish(True)

    def wait(callback: Any) -> None:
        """Wait for the actual retained worker with one fixed deadline; no audit repetition or forced child abandonment."""
        if time.monotonic() > deadline:
            receipt["failure_stage"] = "owned-workflow-deadline"
            finish(True)
        elif window.busy:
            window.root.after(60, lambda: wait(callback))
        else:
            checked(callback)

    def layout() -> None:
        """Require real active controls and Exit to fit the minimum supported native window."""
        window.root.geometry("980x700")
        window.tabs.tk.call(str(window.tabs), "select", str(window.inputs_page))
        window.root.update()
        widgets: list[ttk.Widget] = [window.run_button, *window.footer_buttons.values()]
        for name in project.ACTIVE_FIELDS[window.mode.get()]:
            widgets.extend(window.field_widgets[name])
        for widget in widgets:
            assert widget.winfo_ismapped()
            assert (
                widget.winfo_rootx() >= window.root.winfo_rootx()
                and widget.winfo_rooty() >= window.root.winfo_rooty()
            )
            assert (
                widget.winfo_rootx() + widget.winfo_width()
                <= window.root.winfo_rootx() + window.root.winfo_width()
            )
            assert (
                widget.winfo_rooty() + widget.winfo_height()
                <= window.root.winfo_rooty() + window.root.winfo_height()
            )
        receipt["minimum_layout"] = {
            "width": 980,
            "height": 700,
            "activeInputsRunAndLifecycleVisible": True,
        }
        window.root.geometry("1260x860")
        window.root.update()

    def rejected() -> None:
        """A duplicate-key selected input must preserve every earlier real result and produce a visible rejection."""
        assert (
            len(window.state.history()) == expected
            and "rejected" in window.status.get().lower()
        )
        receipt["steps"].append("actual-invalid-input-retains-all-bundles")
        finish()

    def licenses() -> None:
        """Inspect the actual bundled text notice window, not a source-only declaration that licenses exist."""
        window.licenses()
        dialogs = [
            child
            for child in window.root.winfo_children()
            if isinstance(child, tk.Toplevel)
        ]
        assert len(dialogs) == 1
        dialog = dialogs[0]
        pending: list[tk.Misc] = [dialog]
        texts: list[tk.Text] = []
        while pending:
            widget = pending.pop()
            if isinstance(widget, tk.Text):
                texts.append(widget)
            pending.extend(widget.winfo_children())
            assert len(pending) < 1000
        assert len(texts) == 1
        text = texts[0].get("1.0", "end")
        assert all(
            value in text
            for value in (
                "Python",
                "Tcl",
                "Tk",
                "cryptography",
                "OpenSSL4.0.3",
                "cffi",
                "unicode-ident-1.0.24",
                "target-lexicon-0.13.5",
                "Rust",
            )
        )
        dialog.destroy()
        receipt["steps"].append("actual-bundled-runtime-license-window")

    def completed(index: int) -> None:
        """Read actual original outputs and inspect real rows; no service response or analysis result is mocked."""
        assert (
            len(window.state.history()) == index + 1
            and window.selected_run == index + 1
        )
        files = window.state.files(index + 1)
        oracle(index, files)
        if index in (1, 9):
            window.view.set(
                "Authenticated inventory and changes"
                if index == 1
                else "Trust, sequences and review scope"
            )
            window.render()
            window.table.selection_set("0")
            window.inspect()
            assert json.loads(window.details.get("1.0", "end"))
            window.root.update()
            capture(
                window,
                output
                / (
                    "selected-evidence.png" if index < 8 else "owner-unknown-review.png"
                ),
            )
        receipt["steps"].append("actual-workflow-" + str(index + 1))
        if index + 1 < expected:
            start(index + 1)
        else:
            progress("runtime-license-window")
            licenses()
            progress("exact-export")
            parent = output / "exact-export"
            parent.mkdir()
            with patch(
                "drkit.desktop.filedialog.askdirectory", return_value=str(parent)
            ):
                window.export_button.invoke()
            target = next(parent.iterdir())
            assert {path.name: path.read_bytes() for path in target.iterdir()} == files
            receipt["steps"].append("actual-exact-export")
            progress("invalid-report-retention")
            selected = output / "not-a-signed-bundle.zip"
            selected.write_bytes(b"not a signed canonical ZIP")
            window.mode.set(project.MODES[1])
            with patch(
                "drkit.desktop.filedialog.askopenfilename", return_value=str(selected)
            ):
                window.choose("bundle", "file")
            window.authorized.set(True)
            window.run_button.invoke()
            wait(rejected)

    def start(index: int) -> None:
        """Prepared scenarios set ordinary controls; a real copied external report is selected through the same chooser."""
        progress("workflow-" + str(index + 1))
        window.prepared.set(
            project.SCENARIOS[index] if index < 8 else project.SCENARIOS[0]
        )
        window.load_prepared()
        assert not window.authorized.get()
        if index == 8:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            from drkit.bundle import build

            key = Ed25519PrivateKey.generate()
            archive = build(
                {"payload/private.txt": b"EXTERNAL-PRIVATE-CONTENT"},
                key.private_bytes_raw(),
                product="demo-service",
                version="1.0.0",
                sequence=1,
                target="portable-source",
                created=1893456000,
                expires=1893459600,
                revision="b" * 40,
            )
            selected = output / "authorized.zip"
            public = output / "separate-trust-public.bin"
            selected.write_bytes(archive)
            public.write_bytes(key.public_key().public_bytes_raw())
            window.mode.set(project.MODES[1])
            window.values["minimum_sequence"].set("0")
            with patch(
                "drkit.desktop.filedialog.askopenfilename", return_value=str(selected)
            ):
                window.choose("bundle", "file")
            with patch(
                "drkit.desktop.filedialog.askopenfilename", return_value=str(public)
            ):
                window.choose("trusted_key", "file")
        if index == 9:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )

            from drkit.bundle import build
            from drkit.contracts import Policy
            from drkit.deploy import activate, initialize

            key = Ed25519PrivateKey.generate()

            def package(sequence: int, content: bytes) -> bytes:
                """Build two inert owned versions with the original real signing engine, never persist a signing key."""
                return build(
                    {"payload/private.txt": content},
                    key.private_bytes_raw(),
                    product="demo-service",
                    version=f"1.{sequence}.0",
                    sequence=sequence,
                    target="portable-source",
                    created=1893456000,
                    expires=1893459600,
                    revision="c" * 40,
                )

            initial, candidate = (
                package(1, b"EXTERNAL-PRIVATE-CONTENT initial"),
                package(2, b"EXTERNAL-PRIVATE-CONTENT candidate"),
            )
            public = output / "deployment-trust-public.bin"
            public.write_bytes(key.public_key().public_bytes_raw())
            deployment = output / "authorized-owned-deployment"
            initialize(deployment)
            active = activate(
                deployment,
                initial,
                public.read_bytes(),
                Policy("demo-service", "portable-source", 1893456300),
                None,
            )
            selected = output / "deployment-candidate.zip"
            selected.write_bytes(candidate)
            window.mode.set(project.MODES[2])
            window.values["expected"].set(active["current"])
            window.values["operator"].set("native-reviewer")
            window.values["medium"].set("native-transfer")
            for field, path in (("bundle", selected), ("trusted_key", public)):
                with patch(
                    "drkit.desktop.filedialog.askopenfilename", return_value=str(path)
                ):
                    window.choose(field, "file")
            with patch(
                "drkit.desktop.filedialog.askdirectory", return_value=str(deployment)
            ):
                window.choose("deployment", "directory")
        layout()
        window.authorized.set(True)
        window.run_button.invoke()
        wait(lambda: completed(index))

    def begin() -> None:
        """A separate real process reopens all exact bundles without rerunning services or recomputing a prior report."""
        if reopen:
            assert len(window.state.history()) == expected
            for identity in range(1, expected + 1):
                window.history_table.selection_set(str(identity))
                window.open_button.invoke()
                assert window.selected_run == identity
                oracle(identity - 1, window.state.files(identity))
            receipt["steps"].append("actual-process-reopen-all-exact-bundles")
            finish()
        else:
            assert not window.state.history()
            window.run_button.invoke()
            assert (
                not window.state.history()
                and "permission" in window.status.get().lower()
            )
            start(0)

    window.root.report_callback_exception = callback_failed
    checked(begin)
