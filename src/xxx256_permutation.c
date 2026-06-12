#include "xxx256_internal.h"

static const uint64_t XXX256_ROUND_CONSTANTS[64] = {
    UINT64_C(0x96C63B1D38F1FEE8), UINT64_C(0xFF70D57E4F08A715),
    UINT64_C(0xA158681DC36BD31B), UINT64_C(0x62A3D7251C80A27D),
    UINT64_C(0xECCF3FE15A2C9C79), UINT64_C(0xEE3E72EC7632FB01),
    UINT64_C(0x5787C1D2806E7EB7), UINT64_C(0x7B1B08B32E33EF8A),
    UINT64_C(0xF5660565ECCF2AD5), UINT64_C(0x6EBACE80B206A1C0),
    UINT64_C(0x2DE7C0945FF4DC83), UINT64_C(0x97A68224FA1875FA),
    UINT64_C(0xF5D7AFC1CC6C7B91), UINT64_C(0x92EE7E5015D46726),
    UINT64_C(0x35B8AC16C0D2C668), UINT64_C(0x21B302BB72E7F9E4),
    UINT64_C(0x091B21BFDCEECF17), UINT64_C(0x6ADA019A2F943749),
    UINT64_C(0x077C66BFA2E1ED67), UINT64_C(0x013075217689977D),
    UINT64_C(0xE9043A9A52C8FB13), UINT64_C(0xD2CE4841577BCE25),
    UINT64_C(0xC7270BAF531010F9), UINT64_C(0xAE03D354969D2E98),
    UINT64_C(0xF3C9E95558A2B2C5), UINT64_C(0xC6F59D0A4127E6E0),
    UINT64_C(0x8CB7BD84C2DA112D), UINT64_C(0x2CD95468A3604E4F),
    UINT64_C(0xD751AF7D59DAFD13), UINT64_C(0x13E66CA652266C29),
    UINT64_C(0x5890F6974FFE0AB1), UINT64_C(0x7062243CAA7D7AE4),
    UINT64_C(0xC0AFBC469109B911), UINT64_C(0x763FF274F521CE23),
    UINT64_C(0x957354F1A782657F), UINT64_C(0x8B916B365411DE75),
    UINT64_C(0x3A5440F68612C089), UINT64_C(0xB9076A6B792FE748),
    UINT64_C(0x766AA0DECDC16A86), UINT64_C(0x151DC1353EF689D3),
    UINT64_C(0x8C2D6000D8137000), UINT64_C(0x6384470A1EBF56E0),
    UINT64_C(0x771B51C36F11904D), UINT64_C(0xE9AB451D1FF8002D),
    UINT64_C(0x6E5540AB6D185B6D), UINT64_C(0x9D684020578F109B),
    UINT64_C(0xB0CEBFAA8603487A), UINT64_C(0x569DED101A06106A),
    UINT64_C(0xC9F162FAF42F46CA), UINT64_C(0x246AA5983741EAC7),
    UINT64_C(0x5055C42C9BA938D2), UINT64_C(0x06EFE863338C1E23),
    UINT64_C(0x6809635F4896EEDF), UINT64_C(0xDA58539627E394C2),
    UINT64_C(0x5503C1E6C707236B), UINT64_C(0xE30D396D00F697ED),
    UINT64_C(0xF42AB31F76AB2182), UINT64_C(0x3DEEC20D283C5741),
    UINT64_C(0x97ED56E708CFDFAF), UINT64_C(0x9469C929997C4BD0),
    UINT64_C(0x6BF25BBE92A84747), UINT64_C(0x2534181001662609),
    UINT64_C(0x4F630C542C264805), UINT64_C(0x9B32D31A0F46A5D5)
};

static uint64_t rotate_left64(uint64_t value, unsigned distance)
{
    return (value << distance) | (value >> (64u - distance));
}

static void xmx4(
    uint64_t *a,
    uint64_t *b,
    uint64_t *c,
    uint64_t *d,
    unsigned alpha,
    unsigned beta,
    unsigned gamma,
    unsigned delta)
{
    *a += rotate_left64(*b, alpha);
    *d ^= *a;
    *c += rotate_left64(*d, beta);
    *b ^= *c;
    *a ^= (~*c) & *d;
    *b += rotate_left64(*a, gamma);
    *d ^= *b & *c;
    *c ^= rotate_left64(*a, delta);
}

static void permute_lanes_a(xxx256_state *state)
{
    uint64_t saved;

    saved = state->lane[13];
    state->lane[13] = state->lane[6];
    state->lane[6] = state->lane[1];
    state->lane[1] = saved;
    saved = state->lane[10];
    state->lane[10] = state->lane[8];
    state->lane[8] = state->lane[2];
    state->lane[2] = saved;
    saved = state->lane[7];
    state->lane[7] = state->lane[14];
    state->lane[14] = state->lane[3];
    state->lane[3] = saved;
    saved = state->lane[11];
    state->lane[11] = state->lane[5];
    state->lane[5] = state->lane[4];
    state->lane[4] = saved;
    saved = state->lane[15];
    state->lane[15] = state->lane[12];
    state->lane[12] = state->lane[9];
    state->lane[9] = saved;
}

static void permute_lanes_b(xxx256_state *state)
{
    uint64_t saved;

    saved = state->lane[14];
    state->lane[14] = state->lane[5];
    state->lane[5] = state->lane[1];
    state->lane[1] = saved;
    saved = state->lane[8];
    state->lane[8] = state->lane[10];
    state->lane[10] = state->lane[2];
    state->lane[2] = saved;
    saved = state->lane[6];
    state->lane[6] = state->lane[15];
    state->lane[15] = state->lane[3];
    state->lane[3] = saved;
    saved = state->lane[7];
    state->lane[7] = state->lane[9];
    state->lane[9] = state->lane[4];
    state->lane[4] = saved;
    saved = state->lane[12];
    state->lane[12] = state->lane[13];
    state->lane[13] = state->lane[11];
    state->lane[11] = saved;
}

void xxx256_xp1024_permute(xxx256_state *state, unsigned rounds)
{
    unsigned round;
    unsigned column;

    for (round = 0; round < rounds; ++round) {
        state->lane[0] ^= XXX256_ROUND_CONSTANTS[(round * 4u) + 0u];
        state->lane[5] ^= XXX256_ROUND_CONSTANTS[(round * 4u) + 1u];
        state->lane[10] ^= XXX256_ROUND_CONSTANTS[(round * 4u) + 2u];
        state->lane[15] ^= XXX256_ROUND_CONSTANTS[(round * 4u) + 3u];
        state->lane[3] ^= (uint64_t)round << 56;

        for (column = 0; column < 4u; ++column) {
            xmx4(
                &state->lane[column],
                &state->lane[4u + column],
                &state->lane[8u + column],
                &state->lane[12u + column],
                7u, 19u, 41u, 53u);
        }

        permute_lanes_a(state);

        for (column = 0; column < 4u; ++column) {
            xmx4(
                &state->lane[column],
                &state->lane[4u + column],
                &state->lane[8u + column],
                &state->lane[12u + column],
                11u, 29u, 37u, 47u);
        }

        permute_lanes_b(state);
    }
}
