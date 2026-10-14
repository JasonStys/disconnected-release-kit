# Coding and documentation guidelines

Created by Jason Stys. Domain names/contracts are the first layer of self-documentation; comments describe trust boundaries and non-obvious decisions.

Use Python for strict bounded data/contracts and maintained cryptographic interfaces, Bash only for the small OS namespace lifecycle. Typed runtime, cohesive shallow modules, explicit constants, immutable snapshot wrapper, no implicit coercion, no shell interpolation of user code, no generic extractall, no unverified execution, no handwritten crypto. Unknown license/provenance information is labeled rather than invented.

Each authored source file has a purpose description; named functions/classes have docstrings and meaningful parameter names. scripts/code_map.py uses Python AST to generate exact physical definition/parameter/store-variable/attribute locations without executing code. Bash and YAML maps are lexical indexes, not AST claims. Lambda parameters are indexed; repeated assignments retain distinct line locations. Vendor schema/license and hash-generated dependency locks are third-party/generated data, not authored executable code.

Format first, then regenerate maps, stage reviewed files, generate complete README file guide, run all checks and git diff --check. README purpose inventory rejects unknown noncommentable files. Signing keys/bundles/wheels stay in ignored outputs; validate_repo.py and Gitleaks complement human review. Comments/line maps are checked in CI to prevent stale positional documentation.

Prefer full transitive hashes and official primary documentation, fixed error messages and conservative limits. Benchmark honestly; separate unit/branch coverage, real integration evidence and unsupported production properties.
