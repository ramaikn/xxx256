#include "xxx256_independent.h"

#include <stdint.h>
#include <string.h>

typedef struct independent_state {
    uint64_t word[16];
} independent_state;

static const uint64_t ROUND_CONSTANT[16][4] = {
    { UINT64_C(0x96C63B1D38F1FEE8), UINT64_C(0xFF70D57E4F08A715), UINT64_C(0xA158681DC36BD31B), UINT64_C(0x62A3D7251C80A27D) },
    { UINT64_C(0xECCF3FE15A2C9C79), UINT64_C(0xEE3E72EC7632FB01), UINT64_C(0x5787C1D2806E7EB7), UINT64_C(0x7B1B08B32E33EF8A) },
    { UINT64_C(0xF5660565ECCF2AD5), UINT64_C(0x6EBACE80B206A1C0), UINT64_C(0x2DE7C0945FF4DC83), UINT64_C(0x97A68224FA1875FA) },
    { UINT64_C(0xF5D7AFC1CC6C7B91), UINT64_C(0x92EE7E5015D46726), UINT64_C(0x35B8AC16C0D2C668), UINT64_C(0x21B302BB72E7F9E4) },
    { UINT64_C(0x091B21BFDCEECF17), UINT64_C(0x6ADA019A2F943749), UINT64_C(0x077C66BFA2E1ED67), UINT64_C(0x013075217689977D) },
    { UINT64_C(0xE9043A9A52C8FB13), UINT64_C(0xD2CE4841577BCE25), UINT64_C(0xC7270BAF531010F9), UINT64_C(0xAE03D354969D2E98) },
    { UINT64_C(0xF3C9E95558A2B2C5), UINT64_C(0xC6F59D0A4127E6E0), UINT64_C(0x8CB7BD84C2DA112D), UINT64_C(0x2CD95468A3604E4F) },
    { UINT64_C(0xD751AF7D59DAFD13), UINT64_C(0x13E66CA652266C29), UINT64_C(0x5890F6974FFE0AB1), UINT64_C(0x7062243CAA7D7AE4) },
    { UINT64_C(0xC0AFBC469109B911), UINT64_C(0x763FF274F521CE23), UINT64_C(0x957354F1A782657F), UINT64_C(0x8B916B365411DE75) },
    { UINT64_C(0x3A5440F68612C089), UINT64_C(0xB9076A6B792FE748), UINT64_C(0x766AA0DECDC16A86), UINT64_C(0x151DC1353EF689D3) },
    { UINT64_C(0x8C2D6000D8137000), UINT64_C(0x6384470A1EBF56E0), UINT64_C(0x771B51C36F11904D), UINT64_C(0xE9AB451D1FF8002D) },
    { UINT64_C(0x6E5540AB6D185B6D), UINT64_C(0x9D684020578F109B), UINT64_C(0xB0CEBFAA8603487A), UINT64_C(0x569DED101A06106A) },
    { UINT64_C(0xC9F162FAF42F46CA), UINT64_C(0x246AA5983741EAC7), UINT64_C(0x5055C42C9BA938D2), UINT64_C(0x06EFE863338C1E23) },
    { UINT64_C(0x6809635F4896EEDF), UINT64_C(0xDA58539627E394C2), UINT64_C(0x5503C1E6C707236B), UINT64_C(0xE30D396D00F697ED) },
    { UINT64_C(0xF42AB31F76AB2182), UINT64_C(0x3DEEC20D283C5741), UINT64_C(0x97ED56E708CFDFAF), UINT64_C(0x9469C929997C4BD0) },
    { UINT64_C(0x6BF25BBE92A84747), UINT64_C(0x2534181001662609), UINT64_C(0x4F630C542C264805), UINT64_C(0x9B32D31A0F46A5D5) }
};

static const uint64_t INITIAL_WORD[8] = {
    UINT64_C(0x6ED3051D38F1FEE8), UINT64_C(0x88E241024F08A715),
    UINT64_C(0xD8A6B6493B6BD31B), UINT64_C(0x927F5D134D70A27D),
    UINT64_C(0x6486C9CEDB7F7C79), UINT64_C(0x65CC81B70F1BBCC1),
    UINT64_C(0xDD383471E7829BF8), UINT64_C(0x13200BB8760A60CF)
};

static const uint8_t PERMUTATION_A[16] = {
    0, 6, 8, 14, 5, 11, 13, 3, 10, 12, 2, 4, 15, 1, 7, 9
};

static const uint8_t PERMUTATION_B[16] = {
    0, 5, 10, 15, 9, 14, 3, 4, 2, 7, 8, 13, 11, 12, 1, 6
};

static uint64_t read_word(const uint8_t *bytes)
{
    uint64_t value = 0u;
    unsigned index;
    for (index = 0; index < 8u; ++index) {
        value |= (uint64_t)bytes[index] << (index * 8u);
    }
    return value;
}

static void write_word(uint8_t *bytes, uint64_t value)
{
    unsigned index;
    for (index = 0; index < 8u; ++index) {
        bytes[index] = (uint8_t)(value >> (index * 8u));
    }
}

static uint64_t rol(uint64_t value, unsigned count)
{
    return (value << count) | (value >> (64u - count));
}

static void erase(void *memory, size_t length)
{
    volatile uint8_t *cursor = (volatile uint8_t *)memory;
    while (length-- != 0u) {
        *cursor++ = 0u;
    }
}

static int overlap(const void *a, size_t a_length, const void *b, size_t b_length)
{
    uintptr_t x;
    uintptr_t y;
    if (a_length == 0u || b_length == 0u || a == NULL || b == NULL) {
        return 0;
    }
    x = (uintptr_t)a;
    y = (uintptr_t)b;
    return x <= y ? (y - x) < a_length : (x - y) < b_length;
}

static void scatter(independent_state *state, const uint8_t positions[16])
{
    independent_state copy;
    unsigned index;
    for (index = 0; index < 16u; ++index) {
        copy.word[positions[index]] = state->word[index];
    }
    *state = copy;
    erase(&copy, sizeof(copy));
}

static void mix_columns(
    independent_state *state,
    unsigned alpha,
    unsigned beta,
    unsigned gamma,
    unsigned delta)
{
    unsigned column;
    for (column = 0; column < 4u; ++column) {
        uint64_t a = state->word[column];
        uint64_t b = state->word[4u + column];
        uint64_t c = state->word[8u + column];
        uint64_t d = state->word[12u + column];

        a += rol(b, alpha);
        d ^= a;
        c += rol(d, beta);
        b ^= c;
        a ^= (~c) & d;
        b += rol(a, gamma);
        d ^= b & c;
        c ^= rol(a, delta);

        state->word[column] = a;
        state->word[4u + column] = b;
        state->word[8u + column] = c;
        state->word[12u + column] = d;
    }
}

static void permutation(independent_state *state, unsigned rounds)
{
    unsigned round;
    for (round = 0; round < rounds; ++round) {
        state->word[0] ^= ROUND_CONSTANT[round][0];
        state->word[5] ^= ROUND_CONSTANT[round][1];
        state->word[10] ^= ROUND_CONSTANT[round][2];
        state->word[15] ^= ROUND_CONSTANT[round][3];
        state->word[3] ^= (uint64_t)round << 56;
        mix_columns(state, 7u, 19u, 41u, 53u);
        scatter(state, PERMUTATION_A);
        mix_columns(state, 11u, 29u, 37u, 47u);
        scatter(state, PERMUTATION_B);
    }
}

static void domain(independent_state *state, uint8_t value)
{
    state->word[15] ^= (uint64_t)value << 56;
}

static uint8_t get_rate(const independent_state *state, size_t offset)
{
    return (uint8_t)(state->word[offset / 8u] >> ((offset % 8u) * 8u));
}

static void put_rate(independent_state *state, size_t offset, uint8_t value)
{
    unsigned shift = (unsigned)((offset % 8u) * 8u);
    uint64_t mask = UINT64_C(0xff) << shift;
    size_t lane = offset / 8u;
    state->word[lane] = (state->word[lane] & ~mask) | ((uint64_t)value << shift);
}

static void start(
    independent_state *state,
    const uint8_t key[32],
    const uint8_t nonce[32])
{
    unsigned index;
    for (index = 0; index < 4u; ++index) {
        state->word[index] = read_word(key + (8u * index));
        state->word[4u + index] = read_word(nonce + (8u * index));
    }
    for (index = 0; index < 8u; ++index) {
        state->word[8u + index] = INITIAL_WORD[index];
    }
    domain(state, UINT8_C(0x01));
    state->word[14] ^= UINT64_C(3);
    permutation(state, 16u);
    for (index = 0; index < 4u; ++index) {
        state->word[8u + index] ^= read_word(key + (8u * index));
        state->word[12u + index] ^= read_word(nonce + (8u * index));
    }
    permutation(state, 16u);
}

static void xor_block(independent_state *state, const uint8_t block[64])
{
    unsigned index;
    for (index = 0; index < 8u; ++index) {
        state->word[index] ^= read_word(block + (8u * index));
    }
}

static void take_aad(independent_state *state, const uint8_t *aad, size_t length)
{
    uint8_t tail[64] = { 0 };
    while (length >= 64u) {
        xor_block(state, aad);
        domain(state, UINT8_C(0x11));
        permutation(state, 10u);
        aad += 64u;
        length -= 64u;
    }
    if (length != 0u) {
        memcpy(tail, aad, length);
    }
    tail[length] ^= UINT8_C(0x01);
    tail[63] ^= UINT8_C(0x80);
    xor_block(state, tail);
    domain(state, UINT8_C(0x12));
    permutation(state, 10u);
    domain(state, UINT8_C(0x30));
    permutation(state, 10u);
    erase(tail, sizeof(tail));
}

static void take_message(
    independent_state *state,
    const uint8_t *input,
    size_t length,
    uint8_t *output,
    int decrypt)
{
    size_t index;
    unsigned word_index;
    while (length >= 64u) {
        for (word_index = 0; word_index < 8u; ++word_index) {
            uint64_t input_word = read_word(input + (word_index * 8u));
            uint64_t output_word = input_word ^ state->word[word_index];
            uint64_t cipher_word = decrypt ? input_word : output_word;
            state->word[word_index] = cipher_word;
            if (output != NULL) {
                write_word(output + (word_index * 8u), output_word);
            }
        }
        domain(state, UINT8_C(0x21));
        permutation(state, 10u);
        input += 64u;
        if (output != NULL) {
            output += 64u;
        }
        length -= 64u;
    }
    for (index = 0; index < length; ++index) {
        uint8_t result = (uint8_t)(input[index] ^ get_rate(state, index));
        put_rate(state, index, decrypt ? input[index] : result);
        if (output != NULL) {
            output[index] = result;
        }
    }
    put_rate(state, length, (uint8_t)(get_rate(state, length) ^ UINT8_C(0x01)));
    put_rate(state, 63u, (uint8_t)(get_rate(state, 63u) ^ UINT8_C(0x80)));
    domain(state, UINT8_C(0x22));
    permutation(state, 10u);
}

static void make_tag(
    independent_state *state,
    const uint8_t key[32],
    uint64_t aad_length,
    uint64_t message_length,
    uint8_t tag[32])
{
    unsigned index;
    state->word[8] ^= aad_length;
    state->word[10] ^= message_length;
    for (index = 0; index < 4u; ++index) {
        state->word[12u + index] ^= read_word(key + (index * 8u));
    }
    domain(state, UINT8_C(0x41));
    permutation(state, 16u);
    for (index = 0; index < 4u; ++index) {
        state->word[8u + index] ^= read_word(key + (index * 8u));
    }
    domain(state, UINT8_C(0x42));
    permutation(state, 16u);
    for (index = 0; index < 4u; ++index) {
        write_word(
            tag + (index * 8u),
            state->word[8u + index] ^ state->word[12u + index] ^
                read_word(key + (index * 8u)));
    }
}

static int same_tag(const uint8_t left[32], const uint8_t right[32])
{
    uint8_t difference = 0u;
    unsigned index;
    for (index = 0; index < 32u; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0u;
}

static xxx256_result validate(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    const uint8_t *tag,
    int opening)
{
    if (key == NULL || nonce == NULL || tag == NULL ||
        (aad_length != 0u && aad == NULL) ||
        (input_length != 0u && (input == NULL || output == NULL))) {
        return XXX256_ERR_INVALID_ARGUMENT;
    }
    if ((uint64_t)aad_length > XXX256_MAX_AAD_SIZE ||
        (uint64_t)input_length > XXX256_MAX_MESSAGE_SIZE) {
        return XXX256_ERR_LIMIT;
    }
    if (input != output && overlap(input, input_length, output, input_length)) {
        return XXX256_ERR_OVERLAP;
    }
    if (overlap(output, input_length, key, 32u) ||
        overlap(output, input_length, nonce, 32u) ||
        overlap(output, input_length, tag, 32u) ||
        (!opening && (overlap(input, input_length, tag, 32u) ||
                      overlap(tag, 32u, key, 32u) ||
                      overlap(tag, 32u, nonce, 32u)))) {
        return XXX256_ERR_OVERLAP;
    }
    return XXX256_OK;
}

xxx256_result xxx256_independent_seal_with_nonce(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    uint8_t tag[XXX256_TAG_SIZE])
{
    independent_state state;
    xxx256_result result = validate(
        key, nonce, aad, aad_length, plaintext, plaintext_length,
        ciphertext, tag, 0);
    if (result != XXX256_OK) {
        return result;
    }
    start(&state, key, nonce);
    take_aad(&state, aad, aad_length);
    take_message(&state, plaintext, plaintext_length, ciphertext, 0);
    make_tag(&state, key, (uint64_t)aad_length, (uint64_t)plaintext_length, tag);
    erase(&state, sizeof(state));
    return XXX256_OK;
}

xxx256_result xxx256_independent_open(
    const uint8_t key[XXX256_KEY_SIZE],
    const uint8_t nonce[XXX256_NONCE_SIZE],
    const uint8_t *aad,
    size_t aad_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    const uint8_t tag[XXX256_TAG_SIZE],
    uint8_t *plaintext)
{
    independent_state state;
    uint8_t calculated[32];
    xxx256_result result = validate(
        key, nonce, aad, aad_length, ciphertext, ciphertext_length,
        plaintext, tag, 1);
    if (result != XXX256_OK) {
        return result;
    }
    start(&state, key, nonce);
    take_aad(&state, aad, aad_length);
    take_message(&state, ciphertext, ciphertext_length, plaintext, 1);
    make_tag(&state, key, (uint64_t)aad_length, (uint64_t)ciphertext_length, calculated);
    if (!same_tag(calculated, tag)) {
        erase(plaintext, ciphertext_length);
        erase(calculated, sizeof(calculated));
        erase(&state, sizeof(state));
        return XXX256_ERR_AUTHENTICATION;
    }
    erase(calculated, sizeof(calculated));
    erase(&state, sizeof(state));

    return XXX256_OK;
}
