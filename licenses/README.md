# Bundled cryptographic runtime notices

The portable distribution uses cryptography 50.0.2's actual Windows wheel, which reports **OpenSSL 4.0.3 29 Sep 2026**. The build records the actual `_rust.pyd` bytes and includes cryptography's Apache/BSD notices, cffi's license and the [unmodified OpenSSL license](OpenSSL-4.0.3-LICENSE.txt).

Exact primary source: https://raw.githubusercontent.com/openssl/openssl/openssl-4.0.3/LICENSE.txt

License SHA256: `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a`. Python's own SSL runtime is a separate component. These notices retain upstream terms; they do not assert FIPS certification, a complete source rebuild or legal clearance. Original SPDX schema terms remain under vendor.


The actual wheel's provider CycloneDX SBOM identifies seven internal cryptography crates and32external crate versions across all targets. The [minimal inventory](cryptography-50.0.2-rust-inventory.json) retains exact registry archive checksums and62 original license/copyright/NOTICE file identities. [Verbatim original texts](cryptography-50.0.2-rust-notices.txt) include Unicode3.0 and LLVM-exception terms; this is a conservative all-target superset rather than a claim that every crate is linked into Windows. Raw provider-local build paths are omitted.

The actual `_rust.pyd` embeds compiler-source commit48a229ceaefd4985c50990b14116b6d856af0985; the official Rust source at that commit reports1.98.1. The full [matching Rust library inventory](RUST-COPYRIGHT-library.html) is retained. The build checks actual pyd identity before applying this captured inventory. No crate code was extracted/executed or dependency changed; no legal certification or claim about every possible third-party obligation is asserted.
