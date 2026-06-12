# XXX-256 Product Requirements Document

**Status:** Frozen experimental research candidate  
**Date:** June 13, 2026  
**Category:** Symmetric authenticated encryption  
**Algorithm:** XXX-256  
**Permutation:** XP-1024  
**Construction:** XD-512  
**Deployment status:** Experimental; prohibited for production data

## 1. Executive Summary

XXX-256 is a research project for a new authenticated encryption with associated data (AEAD) algorithm. Its cryptographic core does not use AES, ChaCha, AEGIS, Ascon, or an external hash, MAC, block cipher, or stream cipher. The design consists of the `XP-1024` permutation and the `XD-512` keyed duplex construction.

The candidate has one fixed parameter set:

| Parameter | Value |
|---|---:|
| State | 1024 bits |
| Rate | 512 bits |
| Capacity | 512 bits |
| Key | 256 bits |
| Nonce | 256 bits |
| Authentication tag | 256 bits |
| Full permutation | 16 rounds |
| Data permutation | 10 rounds |
| State layout | 16 little-endian 64-bit lanes |

The design targets constant-time software, low ciphertext expansion, and a generic Q1 quantum key-search cost near 128 bits. Performance and security claims remain hypotheses until supported by reproducible analysis, public cryptanalysis, independent review, and implementation audits.

Completion of an implementation or favorable benchmark results do not make XXX-256 suitable for production. Production use requires a separate approval process after the release gates in this document have been satisfied.

## 2. Product Definition

XXX-256 is a distinct algorithm, not a wrapper or alias for an existing primitive. The project consists of:

1. `XP-1024`, a public 1024-bit permutation;
2. `XD-512`, a keyed duplex construction built on XP-1024;
3. `XXX-256`, the parameter set specified by this document;
4. a portable reference implementation;
5. an independently developed validation implementation;
6. optimized implementations for selected architectures;
7. known-answer and intermediate-state test vectors;
8. reproducible cryptanalysis models and benchmarks.

Permutation, duplex, ARX, Boolean mixing, domain separation, and SIMD are established techniques. The primary novel component is XP-1024. XD-512 follows the general structure of published permutation-based keyed duplex designs, but its transcript, parameters, and keying method require independent analysis and do not inherit security from another construction.

## 3. Objectives

Objectives are ordered by priority. Performance must not compromise any higher-priority objective.

### P0: Specification and Correctness

- Provide a bit-exact, unambiguous specification.
- Produce identical behavior across implementations, languages, and ISAs.
- Define empty input, partial blocks, length limits, overlap, and error states.
- Require agreement between reference and independent implementations.

### P1: Construction Security

- Target 256-bit classical key recovery resistance.
- Target approximately 128-bit generic Q1 quantum key-search resistance.
- Target confidentiality and integrity up to 256 bits in the nonce-respecting model, subject to the strongest applicable analysis and usage limits.
- Reject the candidate if a full-round attack violates published security gates.

### P2: Implementation Security

- Use constant-time operations on supported software targets.
- Avoid secret-indexed memory access and secret-dependent control flow.
- Return no unauthenticated plaintext and erase provisional output before
  reporting authentication failure.
- Prevent undefined behavior, memory safety defects, and unchecked arithmetic overflow.

### P3: Performance

- Be competitive with optimized ChaCha20-Poly1305 in portable software.
- Be competitive with AES-256-GCM on systems without dedicated AES support.
- Evaluate performance against hardware-accelerated AES-256-GCM without weakening the design to improve benchmarks.

### P4: Integration

- Keep ciphertext body length equal to plaintext length.
- Limit detached raw overhead to the 32-byte tag.
- Expose one parameter profile to avoid downgrade and parameter confusion.
- Provide a high-level API that generates nonces and enforces local limits.

## 4. Non-Goals

XXX-256 does not:

- claim security from large parameters alone;
- authorize production use before completion of the release process;
- guarantee superior performance on every platform or message size;
- claim Q2 security;
- conceal message length, timing, endpoint identity, or traffic patterns;
- provide password-based encryption without an external KDF;
- provide key exchange, a KEM, or digital signatures;
- protect a compromised key or endpoint;
- provide physical side-channel resistance without platform countermeasures;
- treat statistical randomness tests as evidence of cryptographic security.

## 5. Threat Model

The adversary may know the complete specification, constants, source code, and test vectors; choose inputs as permitted by the relevant security game; issue adaptive encryption and verification queries; attack multiple keys and users; retain ciphertext for future attacks; use classical computation or local quantum computation in the Q1 model; submit malformed or boundary-case inputs; and observe software timing at realistic resolution.

The primitive does not protect against stolen keys, process compromise, malicious compilers, binary replacement, rollback or cloning that causes nonce reuse, fault injection, or physical leakage without dedicated countermeasures.

## 6. Security Targets

### 6.1 Claim Model

XXX-256 targets nonce-respecting authenticated encryption. Each key and nonce pair must be unique. The effective security claim is bounded by the minimum of:

```text
key-search security
permutation security
construction security
capacity and generic-attack security
tag and forgery security
multi-key security
data-complexity limits
implementation security
```

No final numerical claim may be made before publication of a construction bound and permutation-specific cryptanalysis.

### 6.2 Quantum Model

The primary quantum model is Q1: the adversary may perform local quantum computation but interacts with encryption and decryption oracles classically.

- A 256-bit key targets approximately `2^128` generic quantum key-search queries.
- A 512-bit capacity avoids an immediate generic capacity bottleneck below the 256-bit classical target.
- A 256-bit tag avoids an obvious classical bottleneck from tag length.
- Q2 security is not claimed.
- Grover-style estimates do not compensate for structural weaknesses.

### 6.3 Generic Duplex Margin

Published generic attacks on some public duplex families reach approximately `2^(2c/3)` complexity for capacity `c` under specific models. For `c = 512`, this is approximately `2^341`. This value is a capacity rationale, not a proof for XD-512 or XP-1024.

## 7. Fixed Parameters

| Parameter | Value |
|---|---:|
| Key | 32 bytes |
| Nonce | 32 bytes |
| Tag | 32 bytes |
| State | 128 bytes |
| State representation | 16 x `uint64_t` |
| Matrix representation | 4 rows x 4 columns |
| Rate | 64 bytes |
| Capacity | 64 bytes |
| Full schedule | 16 rounds |
| Data schedule | 10 rounds |
| Byte order | Little-endian |
| Rotation | 64-bit rotate-left |
| Detached expansion | 32 bytes |
| Default nonce source | Operating-system CSPRNG |

These parameters are frozen for all implementations and test vectors covered by this specification. Any change requires a specification revision and a new cryptanalysis review period.

## 8. XP-1024 Permutation

### 8.1 State Layout

The state contains sixteen unsigned 64-bit lanes:

```text
S[ 0] S[ 1] S[ 2] S[ 3]
S[ 4] S[ 5] S[ 6] S[ 7]
S[ 8] S[ 9] S[10] S[11]
S[12] S[13] S[14] S[15]
```

Bytes `8*i` through `8*i+7` map to `S[i]` in little-endian order. Addition is modulo `2^64`. Every rotation distance is a public constant in `1..63`.

### 8.2 XMX4 Word Mixer

For lanes `(a, b, c, d)` and rotation tuple `(alpha, beta, gamma, delta)`, execute the following assignments in order, using the latest value produced by each preceding assignment:

```text
a = a + ROTL64(b, alpha)
d = d XOR a
c = c + ROTL64(d, beta)
b = b XOR c
a = a XOR ((NOT c) AND d)
b = b + ROTL64(a, gamma)
d = d XOR (b AND c)
c = c XOR ROTL64(a, delta)
```

The mixer is reversible because every step is an XOR assignment or modular addition involving lanes available when the inverse is evaluated.

```text
RA = (7, 19, 41, 53)
RB = (11, 29, 37, 47)
```

The tuple selection requires evaluation against rotational, differential, and linear attacks; the selected distances are not themselves evidence of safety.

### 8.3 Lane Permutations

Treat each lane as coordinate `(r, c)` in `Z4 x Z4`.

```text
PI_A: (r, c) -> ((r + c) mod 4, (r + 2*c) mod 4)
PI_B: (r, c) -> ((2*r + c) mod 4, (r + c) mod 4)
```

Both mappings are bijective modulo 4. Implementations must use generated source-to-destination tables or an equivalent mapping with unambiguous semantics.

### 8.4 Round Constants

Round constants are public and provide no secret entropy. Initialize:

```text
x = 0x3356363532585858
```

For each constant, using unsigned 64-bit arithmetic:

```text
x = x XOR (x << 13)
x = x XOR (x >> 7)
x = x XOR (x << 17)
RC = x
```

Left-shift overflow is discarded modulo `2^64`. Generate four constants per round. The canonical table and its checksum must be reproducible from the published generator.

### 8.5 Round Function

For round index `i`:

1. XOR four sequential round constants into `S[0]`, `S[5]`, `S[10]`, and `S[15]`.
2. Set `S[3] = S[3] XOR (uint64(i) << 56)`.
3. Apply XMX4 with tuple `RA` to each column.
4. Apply `PI_A`.
5. Apply XMX4 with tuple `RB` to each resulting column.
6. Apply `PI_B`.

The four column mixers may run in parallel. The round function contains no table lookup, secret-dependent branch, or multiplication.

### 8.6 Schedules

- `XP16` executes 16 rounds for initialization and finalization.
- `XP10` executes 10 rounds for AAD and message processing.

Each invocation restarts at constant index zero. XP10 uses indexes `0..9` and XP16 uses indexes `0..15`. Shorter schedules are not permitted.

## 9. XD-512 Construction

### 9.1 State Partition

```text
rate     = S[0..7]   = 512 bits
capacity = S[8..15]  = 512 bits
```

The rate participates in the encryption transcript. Capacity lanes are never emitted directly.

### 9.2 Domain Values

| Domain | Value |
|---|---:|
| Initialization | `0x01` |
| AAD full block | `0x11` |
| AAD final block | `0x12` |
| Message full block | `0x21` |
| Message final block | `0x22` |
| AAD-to-message transition | `0x30` |
| Finalization pass one | `0x41` |
| Finalization pass two | `0x42` |
| Reserved version/profile binding | `0x50` |

Inject a domain byte into the most significant byte of `S[15]`. During initialization, XOR version word `0x0000000000000003` into `S[14]`. The reserved `0x50` value is not injected unless a future transcript explicitly defines a permutation point for it.

### 9.3 Padding

Final blocks use byte-oriented `10*1` padding in a zero-initialized 64-byte rate block:

```text
block[len] XOR= 0x01
block[63]  XOR= 0x80
```

A final block is always processed, including for empty input and input whose length is an exact multiple of 64 bytes.

### 9.4 Initialization

Given key `K[32]` and nonce `N[32]`:

1. Load the key into `S[0..3]`.
2. Load the nonce into `S[4..7]`.
3. Load eight IV words into `S[8..15]`. Generate the IV with the constant procedure in Section 8.4 using seed `0x5649363532585858`.
4. Inject initialization domain `0x01` and version word `3`.
5. Apply XP16.
6. XOR the key into `S[8..11]`.
7. XOR the nonce into `S[12..15]`.
8. Apply XP16.

### 9.5 AAD Processing

For each complete 64-byte AAD block, XOR the block into the rate, inject domain `0x11`, and apply XP10. Process the final padded block with domain `0x12` and XP10. After all AAD, inject transition domain `0x30` and apply XP10 once.

### 9.6 Encryption

For each complete plaintext block `M`:

```text
C = M XOR rate(S)
rate(S) = C
inject domain 0x21
S = XP10(S)
```

For a final block of length `len`:

1. Compute `C[j] = M[j] XOR rate(S)[j]` for `0 <= j < len`.
2. Replace rate bytes `0..len-1` with the ciphertext.
3. XOR `0x01` into rate byte `len`.
4. XOR `0x80` into rate byte 63.
5. Inject domain `0x22`.
6. Apply XP10.

The final-block operation always runs, including for empty messages and exact multiples of the rate.

### 9.7 Decryption

For each ciphertext byte, derive plaintext by XORing the ciphertext with the current rate byte, then replace that rate byte with the ciphertext. Continue with the same domains, padding, and permutations used for encryption.

An implementation may recover plaintext while authenticating in one pass, but
must erase the complete provisional output before returning an authentication
error. Applications must not expose or concurrently inspect the output buffer
until the operation returns successfully. Implementations with stronger
isolation requirements may authenticate in a first pass or decrypt into private
scratch storage.

### 9.8 Finalization

Encode AAD length and plaintext length in bytes as unsigned 128-bit little-endian integers. XOR the AAD length into `S[8..9]` and plaintext length into `S[10..11]`, then:

1. XOR the key into `S[12..15]`.
2. Inject domain `0x41`.
3. Apply XP16.
4. XOR the key into `S[8..11]`.
5. Inject domain `0x42`.
6. Apply XP16.
7. For `i = 0..3`, compute `T[i] = S[8+i] XOR S[12+i] XOR K[i]`.

Serialize `T[0] || T[1] || T[2] || T[3]` in little-endian order to produce the 32-byte authentication tag.

Finalization requires dedicated analysis for key recovery, key commitment, forgery, internal collisions, and fault behavior.

## 10. Nonce Management

The low-level construction accepts exactly 32 nonce bytes and maintains no nonce history. A key and nonce pair must never be reused.

The safe API obtains a nonce from the operating-system CSPRNG and returns it with the ciphertext. At the limit of `2^32` encryptions per key, ideal random nonce collision probability is approximately `2^-193`.

XXX-256 does not claim nonce-misuse resistance. Suspected reuse requires immediate key retirement, identification of affected ciphertexts, and analysis for plaintext relations, state recovery, and forgery.

## 11. API Requirements

### 11.1 Safe Single-Shot API

```text
seal(key[32], aad, plaintext)
    -> nonce[32], ciphertext[plaintext.length], tag[32]

open(key[32], nonce[32], aad, ciphertext, tag[32])
    -> plaintext[ciphertext.length] | authentication_error
```

### 11.2 Manual Nonce API

```text
seal_with_nonce(key[32], nonce[32], aad, plaintext)
    -> ciphertext, tag[32]
```

The manual nonce API must be isolated and clearly identify nonce uniqueness as a caller responsibility.

### 11.3 Behavioral Requirements

- Nonce and tag lengths are exactly 32 bytes.
- Tag comparison is constant-time with respect to tag contents.
- Authentication failure maps to one public error.
- Exact input/output aliasing may be supported; partial overlap is rejected.
- The low-level core performs no heap allocation where the language permits.
- Secret state is cleared after use.
- Failed decryption returns no unauthenticated plaintext and wipes provisional
  output before returning. Concurrent observation during decryption is outside
  the single-pass API contract.

## 12. Experimental Usage Limits

These are hard experimental caps, not a security proof.

| Limit | Value |
|---|---:|
| Plaintext per message | `2^30` bytes |
| AAD per message | `2^30` bytes |
| Messages per key | `2^32` |
| Total plaintext per key | `2^44` bytes |
| Failed verifications per key | `2^24` |
| Tag length | 32 bytes |
| Nonce length | 32 bytes |

Implementations must enforce per-message limits. Stateful high-level contexts must enforce locally observable per-key limits. Cross-process, rollback, clone, and distributed-key enforcement remain operational responsibilities.

## 13. Experimental Envelope

Detached raw operation has a 32-byte tag overhead. A self-contained payload with nonce and tag has 64 bytes of cryptographic overhead.

| Field | Size |
|---|---:|
| Magic `XX3R` | 4 bytes |
| Version | 1 byte |
| Algorithm | 1 byte |
| Flags | 2 bytes |
| Nonce | 32 bytes |
| Ciphertext | Plaintext length |
| Tag | 32 bytes |

Total envelope overhead is 72 bytes. The implementation assigns algorithm byte `1` to XXX-256/XD-512 and requires flags `0x0000`. The complete 40-byte header is authenticated as an AAD prefix. This is not a stable production format.

## 14. Performance Rationale

XP-1024 is structured so four XMX4 columns can execute in parallel vector lanes. A 1024-bit state maps to four 256-bit vectors on AVX2, and the 64-byte rate corresponds to a common cache-line size. The round function uses fixed rotations, addition, XOR, AND, NOT, and fixed lane permutations without lookup tables or multiplication.

This mapping is an implementation rationale only. It establishes neither throughput nor security.

## 15. Performance Evaluation

Required baselines are mature implementations of AES-256-GCM with native acceleration enabled, optimized ChaCha20-Poly1305, Ascon-AEAD128 as a permutation-based reference, and scalar and available SIMD implementations of XXX-256.

Required platforms include x86-64 scalar, AVX2, AVX-512, ARM64 scalar, NEON, RISC-V 64 scalar, and WebAssembly scalar and SIMD where available.

```text
0, 16, 64, 256 bytes
1, 4, 16, 64 KiB
1, 16 MiB
1 GiB
```

| Gate | Criterion |
|---|---|
| T0 | No slower than 2x the fastest baseline on primary targets |
| T1 | Within 20% of the fastest baseline on x86-64 and ARM64 |
| T2 | At least 1.15x faster for one platform and size class |
| T3 | At least 1.10x geometric mean across two CPU families |
| T4 | Faster than hardware AES and optimized ChaCha for medium and large inputs |

T3 is the design target; T4 is optional. Benchmarks must include key setup, nonce generation, AAD, partial blocks, finalization, tag generation, and verification. Round counts must not be reduced in response to benchmark data without a specification revision and renewed cryptanalysis.

## 16. Required Cryptanalysis

XP-1024 and XD-512 must be evaluated against:

- differential, truncated differential, linear, and differential-linear attacks;
- impossible differential, integral, division-property, boomerang, rectangle, and rebound attacks;
- rotational and rotational-XOR attacks;
- slide, symmetry, self-similarity, invariant-subspace, fixed-point, and short-cycle attacks;
- algebraic degree, cube, interpolation, SAT, SMT, and Groebner-basis methods;
- meet-in-the-middle, guess-and-determine, biclique, and TMDTO attacks;
- state recovery, internal collisions, long-message behavior, and repeated blocks;
- exceptional-function generic attacks;
- related-key, chosen-key, weak-key, equivalent-key, and key-collision attacks;
- forgery, truncation, extension, splicing, and reforgeability;
- nonce reuse, nonce collision, multi-key, multi-target, and applicable quantum structural attacks.

Automated models must cover XMX4 invertibility, differential probability, linear correlation, algebraic degree growth, and active-lane propagation.

## 17. Round Security Gates

Every reported attack must state target, attacked rounds, time, data, memory, success probability, and assumptions.

Redesign is mandatory if:

- a practical distinguisher reaches XP10;
- an attack below `2^128` reaches eight or more data rounds;
- state or key recovery below `2^256` reaches XP10;
- an attack below `2^192` reaches twelve or more full rounds;
- full XP16 has a material structural distinguisher below the target;
- trail growth indicates an unstable safety margin.

These thresholds trigger rejection or review; they do not prove security when no matching attack is known.

## 18. Automated Analysis

The project must provide reproducible SAT/SMT models for XMX4 inversion and differential behavior; MILP models for active lanes; rotational-pair, invariant-subspace, fixed-point, and short-cycle searches; algebraic-degree tracking; differential and linear trail searches; and constant, state-layout, and lane-permutation generators.

Models must run from a clean revision and produce pinned output hashes.

## 19. Correctness Testing

The minimum test suite includes:

- 256 known-answer tests and state snapshots after every round;
- every AAD and plaintext length from 0 through 129 bytes;
- every partial-block position and empty inputs;
- length overflow and maximum-limit rejection;
- mutation of every bit position in key, nonce, AAD, ciphertext, and tag;
- differential testing between independent implementations;
- scalar and optimized backend equivalence;
- XP-1024 inverse tests;
- exact in-place operation tests;
- malformed envelope corpora.

## 20. Robustness and Side Channels

A research-candidate release requires coverage-guided fuzzing, property-based state-machine tests, AddressSanitizer, UndefinedBehaviorSanitizer, MemorySanitizer and ThreadSanitizer where applicable, static analysis, strict compiler warnings, dudect or equivalent timing tests, disassembly review, Hamming-weight tests, and allocation and random-source failure tests.

A negative timing result is not proof of constant-time behavior. A positive timing result blocks release until resolved.

## 21. Implementations

The reference implementation uses fixed-width unsigned integers and prioritizes clarity and exact conformance. The independent implementation must be derived from the specification without mechanically copying reference control flow.

Optimized backends may use AVX2, AVX-512, NEON, or equivalent SIMD facilities, but must preserve the transcript, state mapping, and round count. Runtime dispatch must not depend on secret data.

The cryptographic core has no external cryptographic dependency. Tooling may use solvers, fuzzing frameworks, benchmark libraries, and established baseline implementations.

## 22. Statistical Diagnostics

NIST STS, PractRand, TestU01, avalanche, SAC, BIC, and machine-learning distinguishers may be used as diagnostic tests. A failure blocks the candidate until explained. A pass does not increase the security claim. Test volume must be justified by statistical power, and intermediate states should be included where useful for detecting defects or gross bias.

## 23. Required Artifacts

The project must publish the normative algorithm specification; detailed permutation and mode specifications; security targets and construction bounds; permutation rationale and constant generation procedure; an attack tracker; SAT, SMT, and MILP models; reference and independent implementations; known-answer and intermediate-state vectors; benchmark harnesses and raw results; a side-channel report; and a cryptographic change log.

## 24. Development Phases

### Phase 0: Specification Freeze

Freeze XP-1024, XD-512, constants, parameters, mappings, and transcript.

### Phase 1: Correctness

Complete two independent implementations, publish vectors, and run fuzzing and sanitizers.

### Phase 2: Internal Cryptanalysis

Build automated models and analyze XP10, XP16, initialization, finalization, and nonce reuse. Redesign if a security gate fails.

### Phase 3: Optimization

Implement scalar and selected SIMD backends and publish end-to-end comparisons against mature baselines. Performance results do not justify parameter changes.

### Phase 4: Public Research Candidate

Publish the specification, source, models, vectors, results, and reduced-round challenges. Establish a process for reporting cryptanalytic and implementation findings.

### Phase 5: Public Review

Require at least 36 months of public review after the latest material freeze and at least two independent professional cryptographic reviews. A material change restarts the review period.

### Phase 6: Production Evaluation

Production evaluation may begin only when no critical finding remains open and all claims are supported by published analysis. This document does not approve production deployment.

## 25. Termination Criteria

Return to specification design or terminate the project if XP10 or XP16 fails a round security gate; key recovery, state recovery, or universal forgery violates the target; a non-negligible weak-key class is found; nonce reuse enables simple key recovery; construction bounds do not support the usage limits; constant-time implementation is impractical; performance gains exist only in permutation-only benchmarks; implementations cannot maintain exact equivalence; results are not reproducible; or independent review does not support the principal claims.

## 26. Research Candidate Acceptance

XXX-256 may be described as a public research candidate only when:

- the specification is complete and bit-exact;
- constants and mappings are reproducible;
- independent implementations agree;
- known-answer and intermediate-state vectors are published;
- automated analysis is reproducible;
- no internal attack violates the round gates;
- fair benchmarks and raw data are published;
- all known limitations are documented;
- experimental status is visible in APIs and documentation.

These criteria do not constitute production acceptance.

## 27. Primary References

- RFC 9771, *Properties of Authenticated Encryption with Associated Data Algorithms*: https://www.rfc-editor.org/rfc/rfc9771
- NIST, *Post-Quantum Cryptography FAQ*: https://csrc.nist.gov/projects/post-quantum-cryptography/faqs
- Jaques et al., *On the Practical Cost of Grover for AES Key Recovery*: https://csrc.nist.gov/csrc/media/Events/2024/fifth-pqc-standardization-conference/documents/papers/on-practical-cost-of-grover.pdf
- Bonnetain et al., *Improving Generic Attacks Using Exceptional Functions*: https://eprint.iacr.org/2024/488
- Janson and Struck, *Sponge-based Authenticated Encryption: Security against Quantum Attackers*: https://eprint.iacr.org/2022/139
- Liu et al., *Full-permutation Distinguishers and Improved Collisions on Gimli*: https://eprint.iacr.org/2020/744
- Mennink et al., *Security of Full-State Keyed Sponge and Duplex*: https://doi.org/10.1007/978-3-662-48800-3_19
- Khovratovich and Nikolic, *Rotational Cryptanalysis of ARX*: https://doi.org/10.1007/978-3-642-13858-4_19

These references define relevant threat models, generic attacks, and evaluation methods. None of their algorithms is an internal component of XXX-256.

## 28. Parameter Freeze

```text
Algorithm       = XXX-256
Permutation     = XP-1024
Construction    = XD-512 keyed duplex
State           = 1024 bits, 16 x uint64
Rate            = 512 bits
Capacity        = 512 bits
Key             = 256 bits
Nonce           = 256 bits
Tag             = 256 bits
Full schedule   = XP16
Data schedule   = XP10
Byte order      = little-endian
Core operations = ADD64, XOR, AND, NOT, ROTL64, fixed lane permutation
Raw expansion   = 32-byte tag
Quantum model   = Q1
Deployment      = prohibited pending separate production approval
```
