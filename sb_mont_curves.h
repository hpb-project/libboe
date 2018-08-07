/*
 * sb_sw_curves.h: private definitions of the Montgomery curves supported by
 * Sweet B
 *
 * This file is part of Sweet B, a safe, compact, embeddable elliptic curve
 * cryptography library.
 *
 * Sweet B is provided under the terms of the included LICENSE file. All
 * other rights are reserved.
 *
 * Copyright 2017 Wearable Inc.
 *
 */

#ifndef SB_MONT_CURVES_H
#define SB_MONT_CURVES_H

#include "sb_fe.h"

// A Montgomery curve, defined as B * y^2 = x^3 + A * x^2 + x
typedef struct sb_mont_curve_t {
    const sb_prime_field_t* p;
    const sb_mont_private_t u; // the X coordinate of the base point of the curve
    const sb_fe_t a24_r; // R * (A + 2) / 4
} sb_mont_curve_t;

// curve25519 is defined over the prime 2^255 - 19
static const sb_prime_field_t SB_CURVE_X25519_P = {
    .p = SB_FE_CONST(0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                     0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFED),

    // p - 2 has Hamming weight 253. Factors:

    // Hamming weight 105:
    .p_minus_two_f1 =
        SB_FE_CONST(0x00E525982AF70C88, 0x0E525982AF70C880,
                    0xE525982AF70C880E, 0x525982AF70C880E5),

    // Hamming weight 5:
    .p_minus_two_f2 =
        SB_FE_CONST(0, 0, 0, 0x8F),

    .p_mp = (sb_word_t) UINT64_C(0x86BCA1AF286BCA1B),
    .r2_mod_p = SB_FE_CONST(0, 0, 0, 0x000005A4),
    .r_mod_p = SB_FE_CONST(0, 0, 0, 0x26),

    .bits = 255
};

static const sb_mont_curve_t SB_CURVE_X25519 = {
    .p = &SB_CURVE_X25519_P,
    .u = { { 0x9 }},
    .a24_r = SB_FE_CONST(0, 0, 0, 0x468BCC)
};

#endif
