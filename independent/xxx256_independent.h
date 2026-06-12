#ifndef XXX256_INDEPENDENT_H
#define XXX256_INDEPENDENT_H

#include "xxx256.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Independent scalar transcript implementation for differential validation.
 * It intentionally exposes only explicit-nonce operations and is not the
 * recommended application API.
 */
xxx256_result xxx256_independent_seal_with_nonce(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE]);

xxx256_result xxx256_independent_open(
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
