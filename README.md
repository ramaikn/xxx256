# XXX-256

XXX-256 is an experimental authenticated encryption design implemented in
portable C. It combines the `XP-1024` permutation with the `XD-512` keyed
duplex construction. The fixed parameter set uses 256-bit keys, nonces, and
authentication tags.

> **Security warning:** XXX-256 is a new, unaudited cryptographic design. It
> has not received sufficient public cryptanalysis or independent security
> review. Do not use it to protect production data.

The normative design and security requirements are defined in
[`documentation/XXX-256-PRD.md`](documentation/XXX-256-PRD.md).

## Features

- Portable C99 reference implementation
- 32-byte keys, nonces, and authentication tags
- Single-shot authenticated encryption API
- Nonces generated from the operating system CSPRNG by the safe API
- Single-pass decryption with full output wipe on authentication failure
- Constant-time tag comparison
- Explicit per-message and per-context usage limits
- Experimental self-contained `XX3R` envelope format
- Separate implementation for differential validation
- Reproducible round constant and lane mapping generator

## Build

Requirements:

- CMake 3.16 or later
- A C99-compatible compiler

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The default configuration builds the main library, independent validation
implementation, table generator, and basic example. Optional components can be
disabled with the following CMake options:

```sh
cmake -S . -B build \
  -DXXX256_BUILD_INDEPENDENT=OFF \
  -DXXX256_BUILD_TOOLS=OFF \
  -DXXX256_BUILD_EXAMPLES=OFF
```

## Usage

Include the public header and initialize a key context before encryption or
decryption:

```c
#include <stdint.h>
#include "xxx256.h"

uint8_t key[XXX256_KEY_SIZE] = {0};
xxx256_key_context context;

if (xxx256_key_init(&context, key) != XXX256_OK) {
    return 1;
}

/* Use xxx256_seal() and xxx256_open(). */

xxx256_key_clear(&context);
```

`xxx256_seal()` obtains a fresh nonce from the operating system and returns the
nonce, ciphertext, and tag separately. `xxx256_open()` decrypts and authenticates
in one pass. If authentication fails, it securely wipes the complete plaintext
output before returning an error. Callers must not inspect that buffer from a
concurrent thread or signal handler while `open` is running. Exact in-place
operation is supported; a failed in-place open erases the ciphertext buffer.
Partial buffer overlap is rejected.

See [`examples/basic.c`](examples/basic.c) for a complete example.

## Envelope API

`xxx256_envelope_seal()` and `xxx256_envelope_open()` provide an experimental
self-contained format containing a header, nonce, ciphertext, and tag. Use
`xxx256_envelope_size()` to determine the required output capacity.

The envelope format is not a stable production protocol and may only be used
for research and interoperability testing.

## Manual Nonce API

[`include/xxx256_hazmat.h`](include/xxx256_hazmat.h) exposes encryption with a
caller-provided nonce. Reusing a nonce with the same key is considered
catastrophic. This API is intended only for test vectors, validation, and
controlled research.

## Project Layout

```text
include/                  Public API headers
src/                      Reference implementation
independent/              Independent validation implementation
examples/                 Usage examples
tools/                    Reproducibility utilities
tests/                    Differential and API regression tests
documentation/            Design, review, and performance documents
```

## Current Status

The repository contains an optimized scalar implementation, an independent
comparison implementation, regression tests, and a local benchmark executable.
Run `build/xxx256_benchmark` from a Release build for machine-specific results.
It does not yet provide published known-answer vectors, automated cryptanalysis
models, optimized SIMD backends, cross-platform benchmark results, or a
completed side-channel audit. See
[`documentation/PERFORMANCE.md`](documentation/PERFORMANCE.md) for the current
bottleneck analysis and optimization constraints.

Passing functional tests or producing competitive benchmark results would not
establish the security of this design. The release gates in
[`documentation/XXX-256-PRD.md`](documentation/XXX-256-PRD.md) remain mandatory.
