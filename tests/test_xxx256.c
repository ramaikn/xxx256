#include "xxx256.h"
#include "xxx256_hazmat.h"
#include "xxx256_independent.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fill(uint8_t *buffer, size_t length, uint8_t seed)
{
    size_t index;
    for (index = 0; index < length; ++index) {
        buffer[index] = (uint8_t)(seed + (uint8_t)(index * 29u));
    }
}

static int all_zero(const uint8_t *buffer, size_t length)
{
    size_t index;
    uint8_t value = 0u;
    for (index = 0; index < length; ++index) {
        value |= buffer[index];
    }
    return value == 0u;
}

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static int test_differential_lengths(void)
{
    uint8_t key[32], nonce[32], aad[129], message[129];
    uint8_t cipher[129], independent_cipher[129], output[129];
    uint8_t tag[32], independent_tag[32];
    size_t aad_length, message_length;

    fill(key, sizeof(key), 1u);
    fill(nonce, sizeof(nonce), 2u);
    fill(aad, sizeof(aad), 3u);
    fill(message, sizeof(message), 4u);

    for (aad_length = 0u; aad_length <= sizeof(aad); ++aad_length) {
        for (message_length = 0u; message_length <= sizeof(message); ++message_length) {
            CHECK(xxx256_hazmat_seal_with_nonce(key, nonce, aad, aad_length,
                message, message_length, cipher, tag) == XXX256_OK);
            CHECK(xxx256_independent_seal_with_nonce(key, nonce, aad, aad_length,
                message, message_length, independent_cipher, independent_tag) == XXX256_OK);
            CHECK(memcmp(cipher, independent_cipher, message_length) == 0);
            CHECK(memcmp(tag, independent_tag, sizeof(tag)) == 0);
            memset(output, 0xa5, sizeof(output));
            CHECK(xxx256_hazmat_open(key, nonce, aad, aad_length, cipher,
                message_length, tag, output) == XXX256_OK);
            CHECK(memcmp(output, message, message_length) == 0);
        }
    }
    return 0;
}

static int test_authentication_wipes_output(void)
{
    uint8_t key[32], nonce[32], aad[17], message[97], cipher[97], output[97], tag[32];

    fill(key, sizeof(key), 11u);
    fill(nonce, sizeof(nonce), 12u);
    fill(aad, sizeof(aad), 13u);
    fill(message, sizeof(message), 14u);
    CHECK(xxx256_hazmat_seal_with_nonce(key, nonce, aad, sizeof(aad), message,
        sizeof(message), cipher, tag) == XXX256_OK);

    tag[7] ^= 0x40u;
    memset(output, 0xa5, sizeof(output));
    CHECK(xxx256_hazmat_open(key, nonce, aad, sizeof(aad), cipher,
        sizeof(cipher), tag, output) == XXX256_ERR_AUTHENTICATION);
    CHECK(all_zero(output, sizeof(output)));

    memcpy(output, cipher, sizeof(output));
    CHECK(xxx256_hazmat_open(key, nonce, aad, sizeof(aad), output,
        sizeof(output), tag, output) == XXX256_ERR_AUTHENTICATION);
    CHECK(all_zero(output, sizeof(output)));
    return 0;
}

static int test_safe_and_envelope_apis(void)
{
    xxx256_key_context context;
    uint8_t key[32], aad[9], message[80], nonce[32], cipher[80], output[80], tag[32];
    uint8_t envelope[152];
    size_t envelope_length = 0u, output_length = 0u;

    fill(key, sizeof(key), 21u);
    fill(aad, sizeof(aad), 22u);
    fill(message, sizeof(message), 23u);
    CHECK(xxx256_key_init(&context, key) == XXX256_OK);
    CHECK(xxx256_seal(&context, aad, sizeof(aad), message, sizeof(message),
        nonce, cipher, tag) == XXX256_OK);
    CHECK(xxx256_open(&context, nonce, aad, sizeof(aad), cipher, sizeof(cipher),
        tag, output) == XXX256_OK);
    CHECK(memcmp(output, message, sizeof(message)) == 0);

    CHECK(xxx256_envelope_seal(&context, aad, sizeof(aad), message, sizeof(message),
        envelope, sizeof(envelope), &envelope_length) == XXX256_OK);
    CHECK(envelope_length == sizeof(envelope));
    CHECK(xxx256_envelope_open(&context, aad, sizeof(aad), envelope, envelope_length,
        output, sizeof(output), &output_length) == XXX256_OK);
    CHECK(output_length == sizeof(output));
    CHECK(memcmp(output, message, sizeof(message)) == 0);

    envelope[envelope_length - 1u] ^= 1u;
    memset(output, 0xa5, sizeof(output));
    CHECK(xxx256_envelope_open(&context, aad, sizeof(aad), envelope, envelope_length,
        output, sizeof(output), &output_length) == XXX256_ERR_AUTHENTICATION);
    CHECK(all_zero(output, sizeof(output)));
    xxx256_key_clear(&context);
    return 0;
}

int main(void)
{
    CHECK(test_differential_lengths() == 0);
    CHECK(test_authentication_wipes_output() == 0);
    CHECK(test_safe_and_envelope_apis() == 0);
    puts("all tests passed");
    return 0;
}
