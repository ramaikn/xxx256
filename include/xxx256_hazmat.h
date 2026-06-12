#ifndef XXX256_HAZMAT_H
#define XXX256_HAZMAT_H

#include "xxx256.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DANGER: The caller must guarantee that a nonce is never reused with a key.
 * Nonce reuse is considered catastrophic by the XXX-256 specification.
 * These functions enforce per-message sizes but cannot enforce per-key limits.
 */
xxx256_result xxx256_hazmat_seal_with_nonce(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE]);

xxx256_result xxx256_hazmat_open(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[XXX256_TAG_SIZE],
    uint8_t *plaintext);

#ifdef __cplusplus
}
#endif

#endif
