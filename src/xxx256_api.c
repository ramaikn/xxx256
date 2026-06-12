#include "xxx256_internal.h"
#include "xxx256_hazmat.h"

#include <string.h>

static xxx256_result validate_context(const xxx256_key_context *context)
{
    if (context == NULL || context->_state != XXX256_CONTEXT_READY) {
        return XXX256_ERR_STATE;
    }
    return XXX256_OK;
}

static xxx256_result validate_aad_parts_limit(const xxx256_aad_parts *aad)
{
    if (aad == NULL ||
        (aad->first_length != 0u && aad->first == NULL) ||
        (aad->second_length != 0u && aad->second == NULL)) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    if (aad->first_length > SIZE_MAX - aad->second_length ||
        (uint64_t)(aad->first_length + aad->second_length) > XXX256_MAX_AAD_SIZE) {
        return XXX256_ERR_LIMIT;
    }
    return XXX256_OK;
}

xxx256_result xxx256_key_init(
    xxx256_key_context *context,
    const uint8_t key[XXX256_KEY_SIZE])
{
    uint8_t key_copy[XXX256_KEY_SIZE];

    if (context == NULL || key == NULL) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }

    memcpy(key_copy, key, sizeof(key_copy));
    xxx256_secure_zero(context, sizeof(*context));
    memcpy(context->_key, key_copy, sizeof(context->_key));
    context->_state = XXX256_CONTEXT_READY;
    xxx256_secure_zero(key_copy, sizeof(key_copy));
    return XXX256_OK;
}

void xxx256_key_clear(xxx256_key_context *context)
{
    if (context != NULL) {
        xxx256_secure_zero(context, sizeof(*context));
    }
}

xxx256_result xxx256_context_seal_parts(
    xxx256_key_context *context,
    const xxx256_aad_parts *aad,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t nonce[XXX256_NONCE_SIZE],
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE])
{
    xxx256_result result;

    result = validate_context(context);
    if (result != XXX256_OK) {
        return result;
    }
    if (nonce == NULL || tag == NULL ||
        (plaintext_length != 0u && (plaintext == NULL || ciphertext == NULL))) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    result = validate_aad_parts_limit(aad);
    if (result != XXX256_OK) {
        return result;
    }
    if ((uint64_t)plaintext_length > XXX256_MAX_MESSAGE_SIZE ||
        context->_sealed_messages >= XXX256_MAX_MESSAGES_PER_KEY ||
        context->_sealed_plaintext_bytes > XXX256_MAX_TOTAL_PLAINTEXT_PER_KEY ||
        (uint64_t)plaintext_length >
            XXX256_MAX_TOTAL_PLAINTEXT_PER_KEY - context->_sealed_plaintext_bytes) {
        return XXX256_ERR_LIMIT;
    }
    if (xxx256_ranges_overlap(nonce, XXX256_NONCE_SIZE, context, sizeof(*context)) ||
        xxx256_ranges_overlap(tag, XXX256_TAG_SIZE, context, sizeof(*context)) ||
        xxx256_ranges_overlap(ciphertext, plaintext_length, context, sizeof(*context)) ||
        xxx256_ranges_overlap(nonce, XXX256_NONCE_SIZE, plaintext, plaintext_length) ||
        xxx256_ranges_overlap(nonce, XXX256_NONCE_SIZE, ciphertext, plaintext_length) ||
        xxx256_ranges_overlap(nonce, XXX256_NONCE_SIZE, tag, XXX256_TAG_SIZE) ||
        (plaintext != ciphertext &&
         xxx256_ranges_overlap(plaintext, plaintext_length, ciphertext, plaintext_length)) ||
        xxx256_ranges_overlap(ciphertext, plaintext_length, tag, XXX256_TAG_SIZE) ||
        xxx256_ranges_overlap(plaintext, plaintext_length, tag, XXX256_TAG_SIZE)) {
        return XXX256_ERR_OVERLAP;
    }

    result = xxx256_random_bytes(nonce, XXX256_NONCE_SIZE);
    if (result != XXX256_OK) {
        xxx256_secure_zero(nonce, XXX256_NONCE_SIZE);
        xxx256_secure_zero(tag, XXX256_TAG_SIZE);
        return result;
    }

    result = xxx256_core_seal_parts(
        context->_key,
        nonce,
        aad,
        plaintext,
        plaintext_length,
        ciphertext,
        tag);
    if (result != XXX256_OK) {
        xxx256_secure_zero(nonce, XXX256_NONCE_SIZE);
        xxx256_secure_zero(tag, XXX256_TAG_SIZE);
        return result;
    }

    ++context->_sealed_messages;
    context->_sealed_plaintext_bytes += (uint64_t)plaintext_length;
    return XXX256_OK;
}

xxx256_result xxx256_context_open_parts(
    xxx256_key_context *context,
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const xxx256_aad_parts *aad,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[XXX256_TAG_SIZE],
    uint8_t *plaintext)
{
    xxx256_result result;

    result = validate_context(context);
    if (result != XXX256_OK) {
        return result;
    }
    if (nonce == NULL || tag == NULL ||
        (ciphertext_length != 0u && (ciphertext == NULL || plaintext == NULL))) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    result = validate_aad_parts_limit(aad);
    if (result != XXX256_OK) {
        return result;
    }
    if ((uint64_t)ciphertext_length > XXX256_MAX_MESSAGE_SIZE ||
        context->_failed_verifications >= XXX256_MAX_FAILED_VERIFICATIONS) {
        return XXX256_ERR_LIMIT;
    }
    if (xxx256_ranges_overlap(plaintext, ciphertext_length, context, sizeof(*context))) {
        return XXX256_ERR_OVERLAP;
    }

    result = xxx256_core_open_parts(
        context->_key,
        nonce,
        aad,
        ciphertext,
        ciphertext_length,
        tag,
        plaintext);
    if (result == XXX256_ERR_AUTHENTICATION) {
        ++context->_failed_verifications;
    }
    return result;
}

xxx256_result xxx256_seal(
    xxx256_key_context *context,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t nonce[XXX256_NONCE_SIZE],
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE])
{
    xxx256_aad_parts parts;

    if (xxx256_ranges_overlap(nonce, XXX256_NONCE_SIZE, aad, aad_length)) {
        return XXX256_ERR_OVERLAP;
    }

    parts.first = aad;
    parts.first_length = aad_length;
    parts.second = NULL;
    parts.second_length = 0u;
    return xxx256_context_seal_parts(
        context, &parts, plaintext, plaintext_length, nonce, ciphertext, tag);
}

xxx256_result xxx256_open(
    xxx256_key_context *context,
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[XXX256_TAG_SIZE],
    uint8_t *plaintext)
{
    xxx256_aad_parts parts;

    parts.first = aad;
    parts.first_length = aad_length;
    parts.second = NULL;
    parts.second_length = 0u;
    return xxx256_context_open_parts(
        context, nonce, &parts, ciphertext, ciphertext_length, tag, plaintext);
}

xxx256_result xxx256_hazmat_seal_with_nonce(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE])
{
    xxx256_aad_parts parts;

    parts.first = aad;
    parts.first_length = aad_length;
    parts.second = NULL;
    parts.second_length = 0u;
    return xxx256_core_seal_parts(
        key, nonce, &parts, plaintext, plaintext_length, ciphertext, tag);
}

xxx256_result xxx256_hazmat_open(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[XXX256_TAG_SIZE],
    uint8_t *plaintext)
{
    xxx256_aad_parts parts;

    parts.first = aad;
    parts.first_length = aad_length;
    parts.second = NULL;
    parts.second_length = 0u;
    return xxx256_core_open_parts(
        key, nonce, &parts, ciphertext, ciphertext_length, tag, plaintext);
}

const char *xxx256_result_string(xxx256_result result)
{
    switch (result) {
    case XXX256_OK:
        return "success";
    case XXX256_ERR_AUTHENTICATION:
        return "authentication failed";
    case XXX256_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case XXX256_ERR_LIMIT:
        return "usage limit exceeded";
    case XXX256_ERR_OVERLAP:
        return "unsupported buffer overlap";
    case XXX256_ERR_RANDOM:
        return "operating-system random generator failed";
    case XXX256_ERR_FORMAT:
        return "invalid envelope format";
    case XXX256_ERR_STATE:
        return "invalid key context state";
    case XXX256_ERR_BUFFER_TOO_SMALL:
        return "output buffer too small";
    default:
        return "unknown XXX-256 error";
    }
}
