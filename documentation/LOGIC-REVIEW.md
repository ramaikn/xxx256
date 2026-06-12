# Logic Review - XXX-256 C Draft

Date: 13 June 2026

This is a manual implementation review, not a security audit or proof.

## Transcript checks

- State is 16 little-endian 64-bit lanes; rate is lanes 0 through 7.
- XMX4 assignment order and both rotation tuples match
  [`XXX-256-PRD.md`](XXX-256-PRD.md).
- Every XP round injects four sequential constants, injects the round index,
  applies RA columns, `PI_A`, RB columns, and `PI_B` in that order.
- XP10 and XP16 restart at constant index zero on each invocation.
- Initialization, two full permutations, key/nonce reinjection, AAD transition,
  message processing, length binding, both finalization passes, and tag formula
  match the explicit specification pseudocode.
- Empty and exact-multiple AAD/messages still receive a final padded block.
- The reference and independent sources contain identical round constants, IV
  words, and source-to-destination lane maps.

## API and memory checks

- Message and AAD caps are checked before processing.
- Context counters enforce local message, total plaintext, and failed-open caps.
- Null is accepted only for zero-length data buffers.
- Exact input/output overlap is supported; partial overlap is rejected.
- Safe seal rejects output aliases before invoking the OS RNG.
- Raw open decrypts once and wipes the complete output on tag failure.
- Tag comparison accumulates all byte differences without early exit.
- Secret state, temporary tags, copied keys, failed plaintext, and failed
  envelope output are explicitly cleared with a platform primitive where
  available and a volatile fallback elsewhere.
- Envelope arithmetic is overflow-checked; magic/version/algorithm/flags are
  validated and the complete 40-byte header is an AAD prefix.

## Limitations of this review

- Automated tests were added for lengths 0 through 129,
  reference/independent differential equivalence, round trips, failed-tag
  output wiping, exact in-place failure, the safe API, and the envelope API.
- No C compiler or CMake installation was available in this workspace, so the
  new C test suite and benchmark could not be executed here. A mechanical
  source-to-destination check confirmed both in-place lane cycles match the
  normative mapping tables.
- The local benchmark reports seal/open throughput but is not a substitute for
  cross-platform measurement, profiling, or side-channel testing.
- No cryptanalysis or side-channel audit was performed.
- SIMD backends and formal SAT/SMT/MILP models are not part of this code draft.
- A manual review cannot establish that code is bug-free or that a new cipher
  is secure. The specification explicitly prohibits production deployment.
