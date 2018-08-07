/*
 * sb_mont_context.h: private context structure for Montgomery curves
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

#ifndef SB_MONT_CONTEXT_H
#define SB_MONT_CONTEXT_H

#include "sb_fe.h"
#include "sb_hmac_drbg.h"

// Context used for point operations on Montgomery curves:

typedef struct sb_mont_context_t {
    sb_fe_t z_p;
    union {
        struct {
            sb_fe_t x_p, x_0, z_0, x_1, z_1, t5, t6, t7, t8, k;
        };
        struct {
            sb_hmac_drbg_state_t drbg;
            sb_single_t buf;
        };
    };
} sb_mont_context_t;

#endif
