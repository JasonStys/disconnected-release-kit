# Performance and complexity

Created by Jason Stys. B = total bounded file bytes; N = files (<=256); L = bounded path depth.

Building/verification hash files in O(B), sort names/descriptors in O(N log N), and compare canonical ZIP bytes in O(B). Memory O(B + N); several transient byte buffers may coexist. No decompression occurs. Inventory hashes each carried blob and serializes O(N) records, not file contents. Path ancestor checks O(N * L) with L<=5. Staging reads capped regular files once; builder caps raw payload at 48 MiB before inventory generation.

Activation writes/verifies O(B) bytes and O(N) paths. State history grows to a bounded 1000 entries; no purge is hidden in admission. These are algorithmic bounds, not proof of constant RSS or real-disk latency. Python tracemalloc excludes native cryptography/OpenSSL allocations, OS cache and child pip processes.

scripts/benchmark.py warms up then measures 15 build/verify pairs for an exact synthetic 1 MiB payload. Median timings and Python peak allocations are recorded in docs/reports/benchmark.json after actual CI, not an arbitrary throughput pass threshold. Reproducibility compares byte equality with the same key/metadata; fresh random demo keys naturally change hashes across runs.
