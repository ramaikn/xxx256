#ifndef XXX256_INTERNAL_H
#define XXX256_INTERNAL_H

#include "xxx256.h"

#include <stddef.h>
#include <stdint.h>

#define XXX256_FULL_ROUNDS 16u
#define XXX256_DATA_ROUNDS 10u

#define XXX256_DOMAIN_INITIALIZATION UINT8_C(0x01)
#define XXX256_DOMAIN_AAD_FULL UINT8_C(0x11)
#define XXX256_DOMAIN_AAD_FINAL UINT8_C(0x12)
#define XXX256_DOMAIN_MESSAGE_FULL UINT8_C(0x21)
#define XXX256_DOMAIN_MESSAGE_FINAL UINT8_C(0x22)
#define XXX256_DOMAIN_AAD_TO_MESSAGE UINT8_C(0x30)
#define XXX256_DOMAIN_FINAL_FIRST UINT8_C(0x41)
#define XXX256_DOMAIN_FINAL_SECOND UINT8_C(0x42)

#define XXX256_CONTEXT_READY UINT32_C(0x58323536)

typedef struct xxx256_state {
    uint64_t lane[16];
} xxx256_state;

typedef struct xxx256_aad_parts {
    const uint8_t *first;
    size_t first_length;
    const uint8_t *second;
    size_t second_length;
} xxx256_aad_parts;

uint64_t xxx256_load64_le(const uint8_t source[8]);
void xxx256_store64_le(uint8_t destination[8], uint64_t value);
void xxx256_secure_zero(void *memory, size_t length);
int xxx256_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length);
int xxx256_ranges_overlap(const void *left, size_t left_length, const void *right, size_t right_length);

void xxx256_xp1024_permute(xxx256_state *state, unsigned rounds);

xxx256_result xxx256_core_seal_parts(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const xxx256_aad_parts *aad,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE]);

xxx256_result xxx256_core_open_parts(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const xxx256_aad_parts *aad,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[XXX256_TAG_SIZE],
    uint8_t *plaintext);

xxx256_result xxx256_context_seal_parts(
    xxx256_key_context *context,
    const xxx256_aad_parts *aad,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t nonce[XXX256_NONCE_SIZE],
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE]);

xxx256_result xxx256_context_open_parts(
    xxx256_key_context *context,
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const xxx256_aad_parts *aad,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[XXX256_TAG_SIZE],
    uint8_t *plaintext);

xxx256_result xxx256_random_bytes(uint8_t *output, size_t length);

#endif
