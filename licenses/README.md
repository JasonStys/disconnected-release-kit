# Bundled cryptographic runtime notices

The portable distribution uses cryptography 50.0.2's actual Windows wheel, which reports **OpenSSL 4.0.3 29 Sep 2026**. The build records the actual `_rust.pyd` bytes and includes cryptography's Apache/BSD notices, cffi's license and the [unmodified OpenSSL license](OpenSSL-4.0.3-LICENSE.txt).

Exact primary source: https://raw.githubusercontent.com/openssl/openssl/openssl-4.0.3/LICENSE.txt

License SHA256: `7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a`. Python's own SSL runtime is a separate component. These notices retain upstream terms; they do not assert FIPS certification, a complete source rebuild or legal clearance. Original SPDX schema terms remain under vendor.
