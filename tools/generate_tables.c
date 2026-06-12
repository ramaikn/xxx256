#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define ROUND_SEED UINT64_C(0x3356363532585858)
#define IV_SEED UINT64_C(0x5649363532585858)

static uint64_t next_value(uint64_t value)
{
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    return value;
}

static void store64_le(uint8_t output[8], uint64_t value)
{
    unsigned index;
    for (index = 0; index < 8u; ++index) {
        output[index] = (uint8_t)(value >> (index * 8u));
    }
}

static void make_tables(
    uint64_t round_constants[64],
    uint64_t initialization_vector[8],
    uint8_t pi_a[16],
    uint8_t pi_b[16])
{
    uint64_t value = ROUND_SEED;
    unsigned index;
    unsigned row;
    unsigned column;

    for (index = 0; index < 64u; ++index) {
        value = next_value(value);
        round_constants[index] = value;
    }

    value = IV_SEED;
    for (index = 0; index < 8u; ++index) {
        value = next_value(value);
        initialization_vector[index] = value;
    }

    for (row = 0; row < 4u; ++row) {
        for (column = 0; column < 4u; ++column) {
            index = (row * 4u) + column;
            pi_a[index] = (uint8_t)((((row + column) % 4u) * 4u) +
                                    ((row + (2u * column)) % 4u));
            pi_b[index] = (uint8_t)(((((2u * row) + column) % 4u) * 4u) +
                                    ((row + column) % 4u));
        }
    }
}

static int write_payload(
    const char *path,
    const uint64_t round_constants[64],
    const uint64_t initialization_vector[8],
    const uint8_t pi_a[16],
    const uint8_t pi_b[16])
{
    FILE *file = fopen(path, "wb");
    uint8_t word[8];
    unsigned index;

    if (file == NULL) {
        return 0;
    }
    for (index = 0; index < 64u; ++index) {
        store64_le(word, round_constants[index]);
        if (fwrite(word, 1u, sizeof(word), file) != sizeof(word)) {
            fclose(file);
            return 0;
        }
    }
    for (index = 0; index < 8u; ++index) {
        store64_le(word, initialization_vector[index]);
        if (fwrite(word, 1u, sizeof(word), file) != sizeof(word)) {
            fclose(file);
            return 0;
        }
    }
    if (fwrite(pi_a, 1u, 16u, file) != 16u ||
        fwrite(pi_b, 1u, 16u, file) != 16u) {
        fclose(file);
        return 0;
    }
    return fclose(file) == 0;
}

int main(int argc, char **argv)
{
    uint64_t round_constants[64];
    uint64_t initialization_vector[8];
    uint8_t pi_a[16];
    uint8_t pi_b[16];
    unsigned index;

    make_tables(round_constants, initialization_vector, pi_a, pi_b);

    puts("Round constants:");
    for (index = 0; index < 64u; ++index) {
        printf("0x%016" PRIX64 "%s", round_constants[index],
               (index % 4u) == 3u ? "\n" : " ");
    }
    puts("IV words:");
    for (index = 0; index < 8u; ++index) {
        printf("0x%016" PRIX64 "%s", initialization_vector[index],
               (index % 4u) == 3u ? "\n" : " ");
    }
    puts("PI_A:");
    for (index = 0; index < 16u; ++index) {
        printf("%u%s", (unsigned)pi_a[index], index == 15u ? "\n" : ", ");
    }
    puts("PI_B:");
    for (index = 0; index < 16u; ++index) {
        printf("%u%s", (unsigned)pi_b[index], index == 15u ? "\n" : ", ");
    }

    if (argc == 2 && !write_payload(
            argv[1], round_constants, initialization_vector, pi_a, pi_b)) {
        fprintf(stderr, "failed to write canonical payload: %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    if (argc > 2) {
        fprintf(stderr, "usage: %s [canonical-payload.bin]\n", argv[0]);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
