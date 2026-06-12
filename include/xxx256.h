#ifndef XXX256_H
#define XXX256_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#if CHAR_BIT != 8
#error "XXX-256 requires 8-bit bytes"
#endif

#if !defined(UINT64_MAX) || UINT64_MAX != UINT64_C(0xffffffffffffffff)
#error "XXX-256 requires an exact 64-bit uint64_t"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XXX-256 is an experimental research cipher. It is not approved for
 * production data. See documentation/XXX-256-PRD.md and README.md.
 */

#define XXX256_KEY_SIZE 32u
#define XXX256_NONCE_SIZE 32u
#define XXX256_TAG_SIZE 32u
#define XXX256_RATE_SIZE 64u

#define XXX256_MAX_MESSAGE_SIZE UINT64_C(1073741824)
#define XXX256_MAX_AAD_SIZE UINT64_C(1073741824)
#define XXX256_MAX_MESSAGES_PER_KEY UINT64_C(4294967296)
#define XXX256_MAX_TOTAL_PLAINTEXT_PER_KEY UINT64_C(17592186044416)
#define XXX256_MAX_FAILED_VERIFICATIONS UINT64_C(16777216)

#define XXX256_ENVELOPE_HEADER_SIZE 40u
#define XXX256_ENVELOPE_OVERHEAD 72u

typedef enum xxx256_result {
    XXX256_OK = 0,
    XXX256_ERR_AUTHENTICATION = -1,
    XXX256_ERR_INVALID_ARGUMENT = -2,
    XXX256_ERR_LIMIT = -3,
    XXX256_ERR_OVERLAP = -4,
    XXX256_ERR_RANDOM = -5,
    XXX256_ERR_FORMAT = -6,
    XXX256_ERR_STATE = -7,
    XXX256_ERR_BUFFER_TOO_SMALL = -8
} xxx256_result;

/*
 * The context owns a copy of the key and tracks limits for operations made
 * through this context. It is not thread-safe and must be cleared after use.
 * Applications must not copy, inspect, or modify fields prefixed with '_'.
 */
typedef struct xxx256_key_context {
    uint8_t _key[XXX256_KEY_SIZE];
    uint64_t _sealed_messages;
    uint64_t _sealed_plaintext_bytes;
    uint64_t _failed_verifications;
    uint32_t _state;
} xxx256_key_context;

/* Initialize or securely clear a key context. */
xxx256_result xxx256_key_init(
    xxx256_key_context *context,
    const uint8_t key[XXX256_KEY_SIZE]);

void xxx256_key_clear(xxx256_key_context *context);

/*
 * Safe single-shot seal. A fresh nonce is obtained from the operating system.
 * ciphertext may equal plaintext exactly. Other overlap is rejected.
 */
xxx256_result xxx256_seal(
    xxx256_key_context *context,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t nonce[XXX256_NONCE_SIZE],
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE]);

/*
 * Single-shot open. Plaintext is produced in one pass and the complete output
 * is securely erased before an authentication error is returned. Callers must
 * not read the output concurrently. Exact in-place operation is supported;
 * on authentication failure an in-place ciphertext buffer is erased.
 */
xxx256_result xxx256_open(
    xxx256_key_context *context,
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[XXX256_TAG_SIZE],
    uint8_t *plaintext);

/* Return envelope bytes required for a plaintext length, or 0 on overflow. */
size_t xxx256_envelope_size(size_t plaintext_length);

/*
 * Encode: header || ciphertext || tag. The 40-byte header is authenticated as
 * an AAD prefix. Envelope input and output buffers must not overlap.
 */
xxx256_result xxx256_envelope_seal(
    xxx256_key_context *context,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *envelope,
    size_t envelope_capacity,
    size_t *envelope_length);

/*
 * Decode and authenticate an experimental XX3R envelope. The output length is
 * returned only on success. Envelope input and plaintext output must not
 * overlap.
 */
xxx256_result xxx256_envelope_open(
    xxx256_key_context *context,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *envelope,
    size_t envelope_length,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length);

const char *xxx256_result_string(xxx256_result result);

#ifdef __cplusplus
}
#endif

#endif
