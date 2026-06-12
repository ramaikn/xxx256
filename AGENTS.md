# AGENTS.md

Repository map for agents. Keep this file short and use it as the first stop before changing code.

## What This Repo Is

XXX-256 is an experimental authenticated encryption project in portable C. The codebase contains the main implementation, an independent reference implementation, tests, tooling, and design documents.

## Root Files

- `README.md`: user-facing overview, build steps, usage examples, and current status.
- `CMakeLists.txt`: build configuration for the library, tests, tools, and example.
- `AGENTS.md`: this guide for future agents.

## Folders

- `include/`: public headers.
  - `xxx256.h`: main public API.
  - `xxx256_hazmat.h`: manual-nonce / lower-level API.
- `src/`: primary implementation.
  - `xxx256_api.c`: context API, safe seal/open wrappers, error strings.
  - `xxx256_core.c`: core seal/open logic, state setup, AAD handling, tag generation.
  - `xxx256_permutation.c`: XP-1024 permutation.
  - `xxx256_random.c`: OS CSPRNG nonce generation.
  - `xxx256_envelope.c`: experimental `XX3R` envelope format.
  - `xxx256_internal.h`: internal types and function declarations.
- `independent/`: independent comparison implementation used for differential validation.
  - `xxx256_independent.c`
  - `xxx256_independent.h`
- `tests/`: regression and differential tests.
  - `test_xxx256.c`: round-trip, tamper, overlap, and envelope checks.
- `tools/`: local utilities.
  - `generate_tables.c`: reproducible generator for constants / lane mappings.
  - `benchmark.c`: local throughput benchmark.
- `documentation/`: non-code project docs.
  - `XXX-256-PRD.md`: normative product / security specification.
  - `PERFORMANCE.md`: bottleneck analysis and optimization notes.
  - `LOGIC-REVIEW.md`: manual implementation review.
  - `IMPLEMENTATION-NOTES.md`: implementation-specific decisions and constraints.
  - `CONSTANTS-GENERATION.md`: reproducibility note for constants generation.

## Working Rules

- Treat `documentation/XXX-256-PRD.md` as the source of truth for behavior and security requirements.
- Keep changes scoped; avoid unrelated refactors.
- Preserve constant-time behavior, overlap checks, and secret zeroization.
- Do not weaken authentication or nonce handling for speed.
- If you edit core crypto logic, update or add tests in `tests/test_xxx256.c`.
- If you rename or move files, update `README.md` and any in-repo links.

## Useful Build Targets

- Library: default `cmake -S . -B build` then `cmake --build build`
- Tests: `ctest --test-dir build`
- Benchmark: `build/xxx256_benchmark`

## Notes For Agents

- Prefer `rg --files` for inventory and `rg -n` for text search.
- Use `apply_patch` for edits.
- Do not rewrite or delete user changes unless explicitly asked.
