#include "xxx256_internal.h"

#include <limits.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

static const uint64_t XXX256_INITIALIZATION_VECTOR[8] = {
    UINT64_C(0x6ED3051D38F1FEE8), UINT64_C(0x88E241024F08A715),
    UINT64_C(0xD8A6B6493B6BD31B), UINT64_C(0x927F5D134D70A27D),
    UINT64_C(0x6486C9CEDB7F7C79), UINT64_C(0x65CC81B70F1BBCC1),
    UINT64_C(0xDD383471E7829BF8), UINT64_C(0x13200BB8760A60CF)
};

typedef struct aad_absorber {
    xxx256_state *state;
    uint8_t partial[XXX256_RATE_SIZE];
    size_t partial_length;
} aad_absorber;

uint64_t xxx256_load64_le(const uint8_t source[8])
{
    return ((uint64_t)source[0]) |
           ((uint64_t)source[1] << 8) |
           ((uint64_t)source[2] << 16) |
           ((uint64_t)source[3] << 24) |
           ((uint64_t)source[4] << 32) |
           ((uint64_t)source[5] << 40) |
           ((uint64_t)source[6] << 48) |
           ((uint64_t)source[7] << 56);
}

void xxx256_store64_le(uint8_t destination[8], uint64_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8);
    destination[2] = (uint8_t)(value >> 16);
    destination[3] = (uint8_t)(value >> 24);
    destination[4] = (uint8_t)(value >> 32);
    destination[5] = (uint8_t)(value >> 40);
    destination[6] = (uint8_t)(value >> 48);
    destination[7] = (uint8_t)(value >> 56);
}

void xxx256_secure_zero(void *memory, size_t length)
{
    if (length == 0u) {
        return;
    }
#if defined(_WIN32)
    SecureZeroMemory(memory, length);
#elif defined(XXX256_HAVE_EXPLICIT_BZERO)
    explicit_bzero(memory, length);
#else
    volatile uint8_t *bytes = (volatile uint8_t *)memory;

    while (length != 0u) {
        *bytes++ = 0u;
        --length;
    }
#endif
}

int xxx256_constant_time_equal(const uint8_t *left, const uint8_t *right, size_t length)
{
    uint8_t difference = 0u;
    size_t index;

    for (index = 0; index < length; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0u;
}

int xxx256_ranges_overlap(
    const void *left,
    size_t left_length,
    const void *right,
    size_t right_length)
{
    uintptr_t left_address;
    uintptr_t right_address;

    if (left_length == 0u || right_length == 0u) {
        return 0;
    }
    if (left == NULL || right == NULL) {
        return 0;
    }

    left_address = (uintptr_t)left;
    right_address = (uintptr_t)right;

    if (left_address <= right_address) {
        return (right_address - left_address) < left_length;
    }
    return (left_address - right_address) < right_length;
}

static void inject_domain(xxx256_state *state, uint8_t domain)
{
    state->lane[15] ^= (uint64_t)domain << 56;
}

static uint8_t rate_byte(const xxx256_state *state, size_t index)
{
    size_t lane_index = index / 8u;
    unsigned shift = (unsigned)((index % 8u) * 8u);
    return (uint8_t)(state->lane[lane_index] >> shift);
}

static void set_rate_byte(xxx256_state *state, size_t index, uint8_t value)
{
    size_t lane_index = index / 8u;
    unsigned shift = (unsigned)((index % 8u) * 8u);
    uint64_t mask = UINT64_C(0xff) << shift;

    state->lane[lane_index] =
        (state->lane[lane_index] & ~mask) | ((uint64_t)value << shift);
}

static void initialize_state(
    xxx256_state *state,
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE])
{
    unsigned index;

    for (index = 0; index < 4u; ++index) {
        state->lane[index] = xxx256_load64_le(key + (index * 8u));
        state->lane[4u + index] = xxx256_load64_le(nonce + (index * 8u));
    }
    for (index = 0; index < 8u; ++index) {
        state->lane[8u + index] = XXX256_INITIALIZATION_VECTOR[index];
    }

    inject_domain(state, XXX256_DOMAIN_INITIALIZATION);
    state->lane[14] ^= UINT64_C(3);
    xxx256_xp1024_permute(state, XXX256_FULL_ROUNDS);

    for (index = 0; index < 4u; ++index) {
        state->lane[8u + index] ^= xxx256_load64_le(key + (index * 8u));
        state->lane[12u + index] ^= xxx256_load64_le(nonce + (index * 8u));
    }
    xxx256_xp1024_permute(state, XXX256_FULL_ROUNDS);
}

static void xor_rate_block(xxx256_state *state, const uint8_t block[XXX256_RATE_SIZE])
{
    unsigned lane;

    for (lane = 0; lane < 8u; ++lane) {
        state->lane[lane] ^= xxx256_load64_le(block + (lane * 8u));
    }
}

static void absorb_full_aad_block(xxx256_state *state, const uint8_t block[XXX256_RATE_SIZE])
{
    xor_rate_block(state, block);
    inject_domain(state, XXX256_DOMAIN_AAD_FULL);
    xxx256_xp1024_permute(state, XXX256_DATA_ROUNDS);
}

static void aad_absorb_bytes(aad_absorber *absorber, const uint8_t *input, size_t length)
{
    size_t amount;

    if (absorber->partial_length != 0u) {
        amount = XXX256_RATE_SIZE - absorber->partial_length;
        if (amount > length) {
            amount = length;
        }
        memcpy(absorber->partial + absorber->partial_length, input, amount);
        absorber->partial_length += amount;
        input += amount;
        length -= amount;

        if (absorber->partial_length == XXX256_RATE_SIZE) {
            absorb_full_aad_block(absorber->state, absorber->partial);
            absorber->partial_length = 0u;
        }
    }

    while (length >= XXX256_RATE_SIZE) {
        absorb_full_aad_block(absorber->state, input);
        input += XXX256_RATE_SIZE;
        length -= XXX256_RATE_SIZE;
    }

    if (length != 0u) {
        memcpy(absorber->partial, input, length);
        absorber->partial_length = length;
    }
}

static void absorb_aad(xxx256_state *state, const xxx256_aad_parts *aad)
{
    aad_absorber absorber;
    uint8_t final_block[XXX256_RATE_SIZE];

    absorber.state = state;
    absorber.partial_length = 0u;
    memset(absorber.partial, 0, sizeof(absorber.partial));

    if (aad->first_length != 0u) {
        aad_absorb_bytes(&absorber, aad->first, aad->first_length);
    }
    if (aad->second_length != 0u) {
        aad_absorb_bytes(&absorber, aad->second, aad->second_length);
    }

    memset(final_block, 0, sizeof(final_block));
    if (absorber.partial_length != 0u) {
        memcpy(final_block, absorber.partial, absorber.partial_length);
    }
    final_block[absorber.partial_length] ^= UINT8_C(0x01);
    final_block[XXX256_RATE_SIZE - 1u] ^= UINT8_C(0x80);
    xor_rate_block(state, final_block);
    inject_domain(state, XXX256_DOMAIN_AAD_FINAL);
    xxx256_xp1024_permute(state, XXX256_DATA_ROUNDS);

    inject_domain(state, XXX256_DOMAIN_AAD_TO_MESSAGE);
    xxx256_xp1024_permute(state, XXX256_DATA_ROUNDS);

    xxx256_secure_zero(final_block, sizeof(final_block));
    xxx256_secure_zero(&absorber, sizeof(absorber));
}

static void encrypt_message(
    xxx256_state *state,
    const uint8_t *plaintext,
    size_t length,
    uint8_t *ciphertext)
{
    size_t remaining = length;
    unsigned lane;
    size_t index;

    while (remaining >= XXX256_RATE_SIZE) {
        for (lane = 0; lane < 8u; ++lane) {
            uint64_t message = xxx256_load64_le(plaintext + (lane * 8u));
            uint64_t cipher = message ^ state->lane[lane];
            xxx256_store64_le(ciphertext + (lane * 8u), cipher);
            state->lane[lane] = cipher;
        }
        inject_domain(state, XXX256_DOMAIN_MESSAGE_FULL);
        xxx256_xp1024_permute(state, XXX256_DATA_ROUNDS);
        plaintext += XXX256_RATE_SIZE;
        ciphertext += XXX256_RATE_SIZE;
        remaining -= XXX256_RATE_SIZE;
    }

    for (index = 0; index < remaining; ++index) {
        uint8_t cipher = (uint8_t)(plaintext[index] ^ rate_byte(state, index));
        ciphertext[index] = cipher;
        set_rate_byte(state, index, cipher);
    }
    set_rate_byte(state, remaining, (uint8_t)(rate_byte(state, remaining) ^ UINT8_C(0x01)));
    set_rate_byte(
        state,
        XXX256_RATE_SIZE - 1u,
        (uint8_t)(rate_byte(state, XXX256_RATE_SIZE - 1u) ^ UINT8_C(0x80)));
    inject_domain(state, XXX256_DOMAIN_MESSAGE_FINAL);
    xxx256_xp1024_permute(state, XXX256_DATA_ROUNDS);
}

static void process_ciphertext(
    xxx256_state *state,
    const uint8_t *ciphertext,
    size_t length,
    uint8_t *plaintext)
{
    size_t remaining = length;
    unsigned lane;
    size_t index;

    while (remaining >= XXX256_RATE_SIZE) {
        for (lane = 0; lane < 8u; ++lane) {
            uint64_t cipher = xxx256_load64_le(ciphertext + (lane * 8u));
            uint64_t message = cipher ^ state->lane[lane];
            state->lane[lane] = cipher;
            if (plaintext != NULL) {
                xxx256_store64_le(plaintext + (lane * 8u), message);
            }
        }
        inject_domain(state, XXX256_DOMAIN_MESSAGE_FULL);
        xxx256_xp1024_permute(state, XXX256_DATA_ROUNDS);
        ciphertext += XXX256_RATE_SIZE;
        if (plaintext != NULL) {
            plaintext += XXX256_RATE_SIZE;
        }
        remaining -= XXX256_RATE_SIZE;
    }

    for (index = 0; index < remaining; ++index) {
        uint8_t cipher = ciphertext[index];
        uint8_t message = (uint8_t)(cipher ^ rate_byte(state, index));
        set_rate_byte(state, index, cipher);
        if (plaintext != NULL) {
            plaintext[index] = message;
        }
    }
    set_rate_byte(state, remaining, (uint8_t)(rate_byte(state, remaining) ^ UINT8_C(0x01)));
    set_rate_byte(
        state,
        XXX256_RATE_SIZE - 1u,
        (uint8_t)(rate_byte(state, XXX256_RATE_SIZE - 1u) ^ UINT8_C(0x80)));
    inject_domain(state, XXX256_DOMAIN_MESSAGE_FINAL);
    xxx256_xp1024_permute(state, XXX256_DATA_ROUNDS);
}

static void finalize_tag(
    xxx256_state *state,
    const uint8_t key[XXX256_KEY_SIZE],
    uint64_t aad_length,
    uint64_t message_length,
    uint8_t tag[XXX256_TAG_SIZE])
{
    uint64_t key_lane;
    unsigned index;

    state->lane[8] ^= aad_length;
    state->lane[9] ^= UINT64_C(0);
    state->lane[10] ^= message_length;
    state->lane[11] ^= UINT64_C(0);

    for (index = 0; index < 4u; ++index) {
        state->lane[12u + index] ^= xxx256_load64_le(key + (index * 8u));
    }
    inject_domain(state, XXX256_DOMAIN_FINAL_FIRST);
    xxx256_xp1024_permute(state, XXX256_FULL_ROUNDS);

    for (index = 0; index < 4u; ++index) {
        state->lane[8u + index] ^= xxx256_load64_le(key + (index * 8u));
    }
    inject_domain(state, XXX256_DOMAIN_FINAL_SECOND);
    xxx256_xp1024_permute(state, XXX256_FULL_ROUNDS);

    for (index = 0; index < 4u; ++index) {
        key_lane = xxx256_load64_le(key + (index * 8u));
        xxx256_store64_le(
            tag + (index * 8u),
            state->lane[8u + index] ^ state->lane[12u + index] ^ key_lane);
    }
    key_lane = 0u;
}

static xxx256_result validate_parts(
    const xxx256_aad_parts *aad,
    size_t message_length,
    uint64_t *aad_length)
{
    if (aad == NULL || aad_length == NULL) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    if ((aad->first_length != 0u && aad->first == NULL) ||
        (aad->second_length != 0u && aad->second == NULL)) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    if (aad->first_length > (size_t)XXX256_MAX_AAD_SIZE ||
        aad->second_length > (size_t)XXX256_MAX_AAD_SIZE ||
        aad->first_length > SIZE_MAX - aad->second_length) {
        return XXX256_ERR_LIMIT;
    }
    if ((uint64_t)(aad->first_length + aad->second_length) > XXX256_MAX_AAD_SIZE ||
        (uint64_t)message_length > XXX256_MAX_MESSAGE_SIZE) {
        return XXX256_ERR_LIMIT;
    }
    *aad_length = (uint64_t)(aad->first_length + aad->second_length);
    return XXX256_OK;
}

xxx256_result xxx256_core_seal_parts(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const xxx256_aad_parts *aad,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE])
{
    xxx256_state state;
    uint64_t aad_length;
    xxx256_result result;

    if (key == NULL || nonce == NULL || tag == NULL ||
        (plaintext_length != 0u && (plaintext == NULL || ciphertext == NULL))) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    result = validate_parts(aad, plaintext_length, &aad_length);
    if (result != XXX256_OK) {
        return result;
    }
    if (plaintext != ciphertext &&
        xxx256_ranges_overlap(plaintext, plaintext_length, ciphertext, plaintext_length)) {
        return XXX256_ERR_OVERLAP;
    }
    if (xxx256_ranges_overlap(ciphertext, plaintext_length, tag, XXX256_TAG_SIZE) ||
        xxx256_ranges_overlap(plaintext, plaintext_length, tag, XXX256_TAG_SIZE) ||
        xxx256_ranges_overlap(ciphertext, plaintext_length, key, XXX256_KEY_SIZE) ||
        xxx256_ranges_overlap(ciphertext, plaintext_length, nonce, XXX256_NONCE_SIZE) ||
        xxx256_ranges_overlap(tag, XXX256_TAG_SIZE, key, XXX256_KEY_SIZE) ||
        xxx256_ranges_overlap(tag, XXX256_TAG_SIZE, nonce, XXX256_NONCE_SIZE)) {
        return XXX256_ERR_OVERLAP;
    }

    initialize_state(&state, key, nonce);
    absorb_aad(&state, aad);
    encrypt_message(&state, plaintext, plaintext_length, ciphertext);
    finalize_tag(&state, key, aad_length, (uint64_t)plaintext_length, tag);
    xxx256_secure_zero(&state, sizeof(state));
    return XXX256_OK;
}

xxx256_result xxx256_core_open_parts(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const xxx256_aad_parts *aad,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[XXX256_TAG_SIZE],
    uint8_t *plaintext)
{
    xxx256_state state;
    uint8_t expected_tag[XXX256_TAG_SIZE];
    uint64_t aad_length;
    xxx256_result result;
    int valid;

    if (key == NULL || nonce == NULL || tag == NULL ||
        (ciphertext_length != 0u && (ciphertext == NULL || plaintext == NULL))) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    result = validate_parts(aad, ciphertext_length, &aad_length);
    if (result != XXX256_OK) {
        return result;
    }
    if (ciphertext != plaintext &&
        xxx256_ranges_overlap(ciphertext, ciphertext_length, plaintext, ciphertext_length)) {
        return XXX256_ERR_OVERLAP;
    }
    if (xxx256_ranges_overlap(plaintext, ciphertext_length, key, XXX256_KEY_SIZE) ||
        xxx256_ranges_overlap(plaintext, ciphertext_length, nonce, XXX256_NONCE_SIZE) ||
        xxx256_ranges_overlap(plaintext, ciphertext_length, tag, XXX256_TAG_SIZE)) {
        return XXX256_ERR_OVERLAP;
    }

    initialize_state(&state, key, nonce);
    absorb_aad(&state, aad);
    process_ciphertext(&state, ciphertext, ciphertext_length, plaintext);
    finalize_tag(&state, key, aad_length, (uint64_t)ciphertext_length, expected_tag);
    valid = xxx256_constant_time_equal(expected_tag, tag, XXX256_TAG_SIZE);
    xxx256_secure_zero(expected_tag, sizeof(expected_tag));
    xxx256_secure_zero(&state, sizeof(state));

    if (!valid) {
        xxx256_secure_zero(plaintext, ciphertext_length);
        return XXX256_ERR_AUTHENTICATION;
    }
    return XXX256_OK;
}
