"""Jason Stys: explicit signing, verification and owned-root activation CLI; no auto-execution or key logging."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# definition: parser — line 47
# variable: result — line 49
# variable: sub — line 52
# variable: key — line 53
# variable: builder — line 58
# variable: init — line 67
# variable: status — line 69
# variable: name — line 71
# variable: command — line 72
# definition: main — line 99
# parameter: argv — line 99
# variable: args — line 101
# variable: key — line 105
# variable: stream — line 106
# variable: report — line 110
# variable: bundle — line 115
# variable: stream — line 126
# variable: report — line 128
# variable: report — line 131
# variable: report — line 133
# variable: policy — line 135
# variable: trusted — line 141
# variable: admitted — line 143
# variable: report — line 144
# variable: report — line 152
# variable: report — line 160
# variable: message — line 168
# END CODE MAP

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from drkit.bundle import build, collect, read_file, verify
from drkit.contracts import MAX_BUNDLE, Policy, Rejected
from drkit.deploy import activate, initialize, rollback, state


def parser() -> argparse.ArgumentParser:
    """Define bounded operation choices and independent operator policy arguments."""
    result = argparse.ArgumentParser(
        description="Disconnected Release Kit — created by Jason Stys"
    )
    sub = result.add_subparsers(dest="operation", required=True)
    key = sub.add_parser(
        "demo-keygen",
        help="Explicitly create an unencrypted DEMO key outside version control.",
    )
    key.add_argument("--out", type=Path, required=True)
    builder = sub.add_parser("build")
    builder.add_argument("--source", type=Path, required=True)
    builder.add_argument("--private-key", type=Path, required=True)
    builder.add_argument("--out", type=Path, required=True)
    builder.add_argument("--version", required=True)
    builder.add_argument("--sequence", type=int, required=True)
    builder.add_argument("--created", type=int, required=True)
    builder.add_argument("--expires", type=int, required=True)
    builder.add_argument("--revision", required=True)
    init = sub.add_parser("init")
    init.add_argument("--root", type=Path, required=True)
    status = sub.add_parser("status")
    status.add_argument("--root", type=Path, required=True)
    for name in ("verify", "activate", "rollback"):
        command = sub.add_parser(name)
        command.add_argument("--trusted-key", type=Path, required=True)
        command.add_argument(
            "--now",
            type=int,
            default=None,
            help="Explicit simulated test clock; omit in operational use.",
        )
        command.add_argument("--minimum-sequence", type=int, default=0)
        command.add_argument("--product", required=True)
        command.add_argument("--target", required=True)
        if name != "rollback":
            command.add_argument("--bundle", type=Path, required=True)
        if name != "verify":
            command.add_argument("--root", type=Path, required=True)
            command.add_argument(
                "--expected",
                required=True,
                help="Exact current digest; 'none' for initial activation.",
            )
        if name == "rollback":
            command.add_argument("--release", required=True)
    builder.add_argument("--product", required=True)
    builder.add_argument("--target", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    """Run one explicit operation; output safe counts/digests/state or a fixed rejection without traceback."""
    args = parser().parse_args(argv)
    try:
        if args.operation == "demo-keygen":
            args.out.mkdir(mode=0o700)
            key = Ed25519PrivateKey.generate()
            with (args.out / "demo.key").open("xb") as stream:
                os.chmod(stream.name, 0o600)
                stream.write(key.private_bytes_raw())
            (args.out / "trust.pub").write_bytes(key.public_key().public_bytes_raw())
            report = {
                "demo_keys_created": True,
                "warning": "Unencrypted demo key; provision production trust separately.",
            }
        elif args.operation == "build":
            bundle = build(
                collect(args.source),
                read_file(args.private_key, 32),
                product=args.product,
                version=args.version,
                sequence=args.sequence,
                target=args.target,
                created=args.created,
                expires=args.expires,
                revision=args.revision,
            )
            with args.out.open("xb") as stream:
                stream.write(bundle)
            report = {"bundle_bytes": len(bundle)}
        elif args.operation == "init":
            initialize(args.root)
            report = {"initialized": True}
        elif args.operation == "status":
            report = state(args.root)
        else:
            policy = Policy(
                args.product,
                args.target,
                int(time.time()) if args.now is None else args.now,
                args.minimum_sequence,
            )
            trusted = read_file(args.trusted_key, 32)
            if args.operation == "verify":
                admitted = verify(read_file(args.bundle, MAX_BUNDLE), trusted, policy)
                report = {
                    "sha256": admitted.digest,
                    "product": admitted.metadata["product"],
                    "version": admitted.metadata["version"],
                    "files": len(admitted.files),
                    "sequence": admitted.metadata["sequence"],
                }
            elif args.operation == "activate":
                report = activate(
                    args.root,
                    read_file(args.bundle, MAX_BUNDLE),
                    trusted,
                    policy,
                    None if args.expected == "none" else args.expected,
                )
            else:
                report = rollback(
                    args.root, args.release, args.expected, trusted, policy
                )
        print(
            json.dumps({"author": "Jason Stys", "ok": True, **report}, sort_keys=True)
        )
        return 0
    except (Rejected, OSError) as error:
        message = (
            str(error)
            if isinstance(error, Rejected)
            else "local filesystem operation failed"
        )
        print(json.dumps({"author": "Jason Stys", "ok": False, "error": message}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
