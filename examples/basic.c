#include "xxx256.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    uint8_t key[XXX256_KEY_SIZE] = { 0 };
    const uint8_t aad[] = "contoh metadata";
    const uint8_t message[] = "pesan eksperimen";
    uint8_t nonce[XXX256_NONCE_SIZE];
    uint8_t ciphertext[sizeof(message)];
    uint8_t tag[XXX256_TAG_SIZE];
    uint8_t recovered[sizeof(message)];
    xxx256_key_context context;
    xxx256_result result;

    result = xxx256_key_init(&context, key);
    if (result != XXX256_OK) {
        return 1;
    }

    result = xxx256_seal(
        &context,
        aad, sizeof(aad) - 1u,
        message, sizeof(message),
        nonce, ciphertext, tag);
    if (result != XXX256_OK) {
        fprintf(stderr, "seal: %s\n", xxx256_result_string(result));
        xxx256_key_clear(&context);
        return 1;
    }

    result = xxx256_open(
        &context,
        nonce,
        aad, sizeof(aad) - 1u,
        ciphertext, sizeof(ciphertext),
        tag, recovered);
    if (result != XXX256_OK) {
        fprintf(stderr, "open: %s\n", xxx256_result_string(result));
        xxx256_key_clear(&context);
        return 1;
    }

    printf("Plaintext: %s\n", (const char *)recovered);
    xxx256_key_clear(&context);
    memset(key, 0, sizeof(key));
    return 0;
}
