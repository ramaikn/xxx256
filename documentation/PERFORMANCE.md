# XXX-256 Performance Analysis

Date: 13 June 2026

This analysis covers the portable scalar implementation. Measurements are
machine and compiler specific; use a Release build of `xxx256_benchmark` for
local numbers.

## Implemented Optimizations

1. Decryption is single-pass. A failed authentication wipes the complete output
   before returning. This removes the previous second initialization, AAD pass,
   and ciphertext pass.
2. Both XP-1024 lane maps are fixed in-place three-cycles. The old inner loop
   allocated, copied, and wiped 128 bytes twice per permutation round.
3. Secret erasure uses `SecureZeroMemory` or detected `explicit_bzero`; the
   volatile byte loop remains the portability fallback.
4. Full message blocks already operate on eight 64-bit lanes and support exact
   in-place processing without heap allocation.

For an empty-AAD message with `b` complete 64-byte blocks, the old open path
performed approximately `156 + 20b` XP rounds. The single-pass path performs
`94 + 10b`, the same transcript work as seal. The expected decryption gain is
therefore about 1.66x for tiny messages and approaches 2x as message size grows,
before accounting for validation and memory wiping.

The removed lane-map implementation also caused two 128-byte temporary writes,
two 128-byte copies, and two 128-byte volatile wipes in every XP round. Because
the wipe is observable to the compiler, this traffic could not be eliminated
reliably. Fixed cycles reduce each map to five saved-lane rotations.

## Remaining Bottlenecks

- XP-1024 dominates medium and large messages: ten scalar rounds execute for
  every 64-byte block, plus fixed initialization, AAD transition, and
  finalization permutations.
- Short messages are dominated by fixed permutation cost. The safe seal path
  also pays one OS CSPRNG call per message, so batching application records is
  more effective than micro-optimizing byte loops.
- Byte tails use lane extraction and replacement per byte. The maximum tail is
  63 bytes, so optimizing it has limited impact compared with the block loop.
- Scalar rotate/add/xor dependencies limit instruction-level parallelism.
  SIMD or multi-buffer processing could improve throughput, but requires a
  separately tested backend and must preserve the exact transcript.
- Input validation performs several overlap checks. This is measurable only for
  very small messages and is retained for memory safety.

## Rejected Optimizations

- Nonce pooling in `xxx256_key_context`: unsafe across copied contexts, process
  forks, rollback, and unsynchronized threads. One OS CSPRNG request per safe
  seal is retained.
- Reduced rounds or changed domains: changes the cipher and requires a new
  specification plus cryptanalysis.
- Early-exit tag comparison: creates a timing leak.
- Skipping failed-output wiping: returns unauthenticated plaintext to callers.

## Benchmark Scope

`xxx256_benchmark` measures deterministic-nonce core seal/open throughput at
0, 32, 64, 1024, 16384, and 1048576 bytes. It deliberately excludes RNG from
the core throughput figures. OS RNG latency should be measured separately when
the workload consists primarily of tiny messages.
