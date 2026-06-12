#include "xxx256.h"
#include "xxx256_hazmat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double seconds(clock_t start, clock_t end)
{
    return (double)(end - start) / (double)CLOCKS_PER_SEC;
}

static void run_size(size_t length)
{
    uint8_t key[32] = { 0 }, nonce[32] = { 0 }, tag[32];
    uint8_t *plain = (uint8_t *)malloc(length == 0u ? 1u : length);
    uint8_t *cipher = (uint8_t *)malloc(length == 0u ? 1u : length);
    size_t iterations = length < 1024u ? 20000u : (64u * 1024u * 1024u) / length;
    size_t index;
    clock_t start, end;
    double seal_time, open_time;

    if (plain == NULL || cipher == NULL) {
        fprintf(stderr, "allocation failed\n");
        exit(1);
    }
    memset(plain, 0x5a, length);
    if (iterations < 20u) {
        iterations = 20u;
    }

    start = clock();
    for (index = 0u; index < iterations; ++index) {
        nonce[0] = (uint8_t)index;
        if (xxx256_hazmat_seal_with_nonce(key, nonce, NULL, 0u, plain, length,
                cipher, tag) != XXX256_OK) {
            exit(1);
        }
    }
    end = clock();
    seal_time = seconds(start, end);

    start = clock();
    for (index = 0u; index < iterations; ++index) {
        if (xxx256_hazmat_open(key, nonce, NULL, 0u, cipher, length, tag,
                plain) != XXX256_OK) {
            exit(1);
        }
    }
    end = clock();
    open_time = seconds(start, end);

    printf("%8lu bytes: seal %8.2f MiB/s, open %8.2f MiB/s, open/seal %.3f\n",
        (unsigned long)length,
        seal_time == 0.0 ? 0.0 : ((double)length * (double)iterations) / seal_time / 1048576.0,
        open_time == 0.0 ? 0.0 : ((double)length * (double)iterations) / open_time / 1048576.0,
        seal_time == 0.0 ? 0.0 : open_time / seal_time);
    free(cipher);
    free(plain);
}

int main(void)
{
    static const size_t sizes[] = { 0u, 32u, 64u, 1024u, 16384u, 1048576u };
    size_t index;
    for (index = 0u; index < sizeof(sizes) / sizeof(sizes[0]); ++index) {
        run_size(sizes[index]);
    }
    return 0;
}
