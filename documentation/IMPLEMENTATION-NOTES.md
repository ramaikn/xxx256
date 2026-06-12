# XXX-256 Implementation Notes

[`XXX-256-PRD.md`](XXX-256-PRD.md) is the sole normative product specification. The implemented
API uses one fixed parameter set: a 32-byte key, 32-byte nonce, 32-byte tag,
64-byte rate, XP10 data schedule, and XP16 full schedule. Incremental
processing, file streaming, rekeying, alternate profiles, and nonce-misuse
resistance are outside the current API.

The domain value `0x50` is reserved by the specification but no transcript step
uses it. Initialization injects domain `0x01` into `S[15]` and version word `3`
into `S[14]`. Injecting `0x50` without a specified permutation point would
create a different cipher.

The experimental envelope assigns algorithm byte `1` to XXX-256/XD-512 and
requires flags `0x0000`. Changing either value requires an explicit envelope
format decision.

Raw decryption performs plaintext recovery and authentication in one pass. On
tag failure, the complete output range is securely erased before the function
returns. This removes the second initialization, AAD absorption, and message
permutation pass. The caller must not inspect output concurrently while open is
running. Failed exact in-place decryption intentionally destroys the ciphertext.

XP-1024 lane mappings use fixed in-place three-cycles. This avoids two 128-byte
temporary arrays, two `memcpy` calls, and two secret-memory wipes per round.
The mapping remains source-to-destination equivalent to the normative tables.

Secret erasure uses `SecureZeroMemory` on Windows and `explicit_bzero` when
detected by CMake. Other targets retain the volatile byte-write fallback.

The safe seal API continues to request each nonce directly from the operating
system CSPRNG. User-space nonce pooling was rejected because copied contexts,
threads, and process forks can duplicate pool state and cause catastrophic
key/nonce reuse. The manual nonce API remains limited to controlled research.

The high-level key context enforces limits for operations observed through that
specific context. A stateless C library cannot detect another process, copied
context, rollback, or a different program using the same key. Operational key
management remains outside the primitive, as stated by the specification.

This repository contains scalar reference and independent implementations.
SIMD backends, benchmark claims, cryptanalysis models, KAT publication, and
side-channel reports are later research artifacts. Their absence means this is
an implementation draft, not an accepted research candidate or production
cipher.
