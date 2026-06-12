#include "xxx256_internal.h"

#include <string.h>

#define XXX256_ENVELOPE_VERSION UINT8_C(3)
#define XXX256_ENVELOPE_ALGORITHM UINT8_C(1)

static const uint8_t XXX256_ENVELOPE_MAGIC[4] = {
    (uint8_t)'X', (uint8_t)'X', (uint8_t)'3', (uint8_t)'R'
};

size_t xxx256_envelope_size(size_t plaintext_length)
{
    if ((uint64_t)plaintext_length > XXX256_MAX_MESSAGE_SIZE ||
        plaintext_length > SIZE_MAX - XXX256_ENVELOPE_OVERHEAD) {
        return 0u;
    }
    return plaintext_length + XXX256_ENVELOPE_OVERHEAD;
}

static void write_header(uint8_t header[XXX256_ENVELOPE_HEADER_SIZE])
{
    memcpy(header, XXX256_ENVELOPE_MAGIC, sizeof(XXX256_ENVELOPE_MAGIC));
    header[4] = XXX256_ENVELOPE_VERSION;
    header[5] = XXX256_ENVELOPE_ALGORITHM;
    header[6] = 0u;
    header[7] = 0u;
    memset(header + 8u, 0, XXX256_NONCE_SIZE);
}

static int valid_header(const uint8_t header[XXX256_ENVELOPE_HEADER_SIZE])
{
    return memcmp(header, XXX256_ENVELOPE_MAGIC, sizeof(XXX256_ENVELOPE_MAGIC)) == 0 &&
           header[4] == XXX256_ENVELOPE_VERSION &&
           header[5] == XXX256_ENVELOPE_ALGORITHM &&
           header[6] == 0u &&
           header[7] == 0u;
}

xxx256_result xxx256_envelope_seal(
    xxx256_key_context *context,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *envelope,
    size_t envelope_capacity,
    size_t *envelope_length)
{
    xxx256_aad_parts parts;
    size_t required;
    uint8_t *nonce;
    uint8_t *ciphertext;
    uint8_t *tag;
    xxx256_result result;

    if (envelope_length == NULL) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }

    required = xxx256_envelope_size(plaintext_length);
    if (required == 0u) {
        return XXX256_ERR_LIMIT;
    }
    if (envelope == NULL ||
        (aad_length != 0u && aad == NULL) ||
        (plaintext_length != 0u && plaintext == NULL)) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    if (envelope_capacity < required) {
        return XXX256_ERR_BUFFER_TOO_SMALL;
    }
    if (aad_length > SIZE_MAX - XXX256_ENVELOPE_HEADER_SIZE ||
        (uint64_t)(aad_length + XXX256_ENVELOPE_HEADER_SIZE) > XXX256_MAX_AAD_SIZE) {
        return XXX256_ERR_LIMIT;
    }
    if (xxx256_ranges_overlap(envelope, required, plaintext, plaintext_length) ||
        xxx256_ranges_overlap(envelope, required, aad, aad_length) ||
        xxx256_ranges_overlap(envelope, required, context, sizeof(*context)) ||
        xxx256_ranges_overlap(envelope, required, envelope_length, sizeof(*envelope_length))) {
        return XXX256_ERR_OVERLAP;
    }

    write_header(envelope);
    nonce = envelope + 8u;
    ciphertext = envelope + XXX256_ENVELOPE_HEADER_SIZE;
    tag = ciphertext + plaintext_length;

    parts.first = envelope;
    parts.first_length = XXX256_ENVELOPE_HEADER_SIZE;
    parts.second = aad;
    parts.second_length = aad_length;

    result = xxx256_context_seal_parts(
        context, &parts, plaintext, plaintext_length, nonce, ciphertext, tag);
    if (result != XXX256_OK) {
        xxx256_secure_zero(envelope, required);
        return result;
    }

    *envelope_length = required;
    return XXX256_OK;
}

xxx256_result xxx256_envelope_open(
    xxx256_key_context *context,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *envelope,
    size_t envelope_length,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length)
{
    xxx256_aad_parts parts;
    const uint8_t *nonce;
    const uint8_t *ciphertext;
    const uint8_t *tag;
    size_t ciphertext_length;
    xxx256_result result;

    if (plaintext_length == NULL) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }

    if (envelope == NULL || (aad_length != 0u && aad == NULL)) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    if (envelope_length < XXX256_ENVELOPE_OVERHEAD) {
        return XXX256_ERR_FORMAT;
    }
    if (!valid_header(envelope)) {
        return XXX256_ERR_FORMAT;
    }

    ciphertext_length = envelope_length - XXX256_ENVELOPE_OVERHEAD;
    if ((uint64_t)ciphertext_length > XXX256_MAX_MESSAGE_SIZE ||
        aad_length > SIZE_MAX - XXX256_ENVELOPE_HEADER_SIZE ||
        (uint64_t)(aad_length + XXX256_ENVELOPE_HEADER_SIZE) > XXX256_MAX_AAD_SIZE) {
        return XXX256_ERR_LIMIT;
    }
    if (plaintext_capacity < ciphertext_length) {
        return XXX256_ERR_BUFFER_TOO_SMALL;
    }
    if (ciphertext_length != 0u && plaintext == NULL) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    if (xxx256_ranges_overlap(envelope, envelope_length, plaintext, ciphertext_length) ||
        xxx256_ranges_overlap(aad, aad_length, plaintext, ciphertext_length) ||
        xxx256_ranges_overlap(plaintext, ciphertext_length, plaintext_length, sizeof(*plaintext_length))) {
        return XXX256_ERR_OVERLAP;
    }

    nonce = envelope + 8u;
    ciphertext = envelope + XXX256_ENVELOPE_HEADER_SIZE;
    tag = ciphertext + ciphertext_length;

    parts.first = envelope;
    parts.first_length = XXX256_ENVELOPE_HEADER_SIZE;
    parts.second = aad;
    parts.second_length = aad_length;

    result = xxx256_context_open_parts(
        context, nonce, &parts, ciphertext, ciphertext_length, tag, plaintext);
    if (result != XXX256_OK) {
        return result;
    }

    *plaintext_length = ciphertext_length;
    return XXX256_OK;
}
