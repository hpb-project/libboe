/*
 * sb_mont_lib.c: operations on Montgomery elliptic curves
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

#include "sb_mont_lib.h"
#include "sb_mont_curves.h"
#include "sb_hmac_drbg.h"
#include "sb_test.h"
#include <string.h>

// 5MM + 4A
// See Costello and Smith 2017, Algorithm 2 (xDBL)
// Input: Q = (x_0, z_0)
// Output: 2Q = (x_0, z_0), with x_Q + z_Q in t5 and x_Q - z_Q in t7

static void sb_mont_point_double(sb_mont_context_t c[static const 1],
                                 sb_mont_curve_t const m[static const 1])
{
    // t1 = x_0, t2 = z_0, t3 = x_1, t4 = z_1
    sb_fe_mod_add(&c->t5, &c->x_0, &c->z_0, m->p); // t5 = x_0 + z_0 = v_1
    sb_fe_mont_square(&c->t6, &c->t5, m->p); // t6 = v_1^2 = v_1

    sb_fe_mod_sub(&c->z_0, &c->x_0, &c->z_0, m->p); // t2 = x_0 - z_0 = v_2
    sb_fe_mont_square(&c->t7, &c->z_0, m->p); // t7 = v_2^2 = v_2

    sb_fe_mont_mult(&c->x_0, &c->t6, &c->t7, m->p); // x_0 = v_1 * v_2 = X_2Q

    sb_fe_mod_sub(&c->t6, &c->t6, &c->t7, m->p); // t6 = v_1 - v_2 = v_1
    sb_fe_mont_mult(&c->t8, &m->a24_r, &c->t6, m->p);
    // t8 = ((A + 2) / 4) * v_1 = v_3
    sb_fe_mod_add(&c->t8, &c->t8, &c->t7, m->p); // t8 = v_3 + v_2 = v_3

    c->t7 = c->z_0;
    // t7 = (x_Q - z_Q), saved for use in the differential addition portion of
    // the ladder

    sb_fe_mont_mult(&c->z_0, &c->t6, &c->t8, m->p); // z_0 = v_1 * v_3 = Z_2Q
}

// 6MM + 4A
// See Costello and Smith 2017, Algorithm 1, modified to avoid recomputing
// values already computed in xDBL
// Input: P = (x_1, z_1); x_Q + z_Q = t5; x_Q - z_Q = t7, P - Q = (x_p, z_p)
// Output: P + Q = (x_1, z_1)
static void sb_mont_point_diff_add(sb_mont_context_t c[static const 1],
                                   sb_mont_curve_t const m[static const 1])
{
    // t1 = x_0, t2 = z_0, t3 = x_1, t4 = z_1
    sb_fe_mod_add(&c->t6, &c->x_1, &c->z_1, m->p); // t6 = x_1 + z_1 = v_0
    // v_1 = x_Q - z_Q = t7
    sb_fe_mont_mult(&c->t8, &c->t7, &c->t6, m->p); // t8 = v_1 * v_0 = v_1

    sb_fe_mod_sub(&c->x_1, &c->x_1, &c->z_1, m->p); // t3 = x_1 - z_1 = v_0
    // v_2 = x_Q + z_Q = t5
    sb_fe_mont_mult(&c->t6, &c->t5, &c->x_1, m->p); // t6 = v_2 * v_0 = v_2

    sb_fe_mod_add(&c->t5, &c->t8, &c->t6, m->p); // t5 = v_1 + v_2 = v_3

    sb_fe_mont_square(&c->t7, &c->t5, m->p); // t7 = v_3^2 = v_3

    sb_fe_mod_sub(&c->t5, &c->t8, &c->t6, m->p); // t5 = v_1 - v_2 = v_4
    sb_fe_mont_square(&c->t6, &c->t5, m->p); // t6 = v_4^2 = v_4

    sb_fe_mont_mult(&c->x_1, &c->z_p, &c->t7, m->p); // x_1 = z_p * v_3
    sb_fe_mont_mult(&c->z_1, &c->x_p, &c->t6, m->p); // z_1 = x_p * v_4

}

// The "standard" advice for curve25519 implementors is to use a Montgomery
// ladder with the above doubling and differential addition algorithms and
// with z_p = 1 for efficiency. This routine instead first computes h * P where
// h is the cofactor of the curve, then computes (k / h) * (h * P), which is
// easily computable without an inversion because the input scalar is already
// a multiple of the cofactor (as ensured by the point decoding routine).

// Z blinding is used to prevent side-channel analyses, but is performed
// after the input point is multiplied by the cofactor, ensuring that a Z
// derived from private key material is not multiplied by a small-order point.

// See Genkin, Valenta, and Yarom 2017 for the inspiration for this method,
// though it's not clear why they don't discuss the standard countermeasure
// of projective coordinate randomization (see Coron 1999) at all.

static sb_error_t
sb_mont_point_mult(sb_mont_context_t c[static const 1],
                   const sb_mont_curve_t m[static const 1])
{
    sb_word_t swap = 0;
    sb_bitcount_t t;

    // Put x_p (the original X input) into Montgomery domain
    sb_fe_mont_mult(&c->x_0, &c->x_p, &m->p->r2_mod_p, m->p);

    // Put initial Z into Montgomery domain as well, and temporarily store it
    // in z_1
    sb_fe_mont_mult(&c->z_1, &c->z_p, &m->p->r2_mod_p, m->p);

    // Use an initial z of 1 (R, in Montgomery domain)
    c->z_0 = m->p->r_mod_p;

    // (x_0, z_0) = P

    // Multiply the input point by the cofactor:
    for (t = 0; t < 3; t++) {
        sb_mont_point_double(c, m);
    }

    // If z_0 == 0 then this was a small-order point!
    if (sb_fe_equal(&c->z_0, &m->p->p)) {
        return SB_ERROR_PUBLIC_KEY_INVALID;
    }

    // Now apply the initial Z, after the point has been multiplied by the
    // cofactor. This point will be used in the differential double-and-add
    // portion of the ladder, so it's important that it be blinded here.
    sb_fe_mont_mult(&c->x_p, &c->x_0, &c->z_1, m->p);
    sb_fe_mont_mult(&c->z_p, &c->z_0, &c->z_1, m->p);

    c->x_0 = c->x_p;
    c->z_0 = c->z_p;

    // (x_p, z_p) = (x_0, x_0) = h * P

    // bit 254 is always set, so the ladder starts at h * P, 2 * h * P
    sb_mont_point_double(c, m);
    c->x_1 = c->x_p;
    c->z_1 = c->z_p;
    swap = 1; // equivalent to swapping (x_0, z_0) and (x_1, z_1)

    for (t = SB_FE_BITS - 3; t > 2; t--) {
        // 11MM + 8A per bit
        const sb_word_t k_t = sb_fe_test_bit(&c->k, t);

        swap ^= k_t;
        sb_fe_ctswap(swap, &c->x_0, &c->x_1);
        sb_fe_ctswap(swap, &c->z_0, &c->z_1);
        swap = k_t;

        sb_mont_point_double(c, m);
        sb_mont_point_diff_add(c, m);
    }

    sb_fe_ctswap(swap, &c->x_0, &c->x_1);
    sb_fe_ctswap(swap, &c->z_0, &c->z_1);

    sb_fe_mont_mult(&c->z_1, &c->z_0, &m->p->r2_mod_p, m->p); // z_1 = z_0 * R
    sb_fe_mod_inv_r(&c->z_1, &c->t5, &c->t6, m->p); // z_1 = z_0 ^ -1 * R
    sb_fe_mont_mult(&c->x_p, &c->x_0, &c->z_1, m->p);
    // x = x_0 * z_0 ^ -1 * R * R^-1

    return 0;
}

#ifdef SB_TEST

static _Bool test_mont_point_mult(const sb_fe_t* const g,
                                  const sb_fe_t* const n)
{
    sb_fe_t n4 = *n;
    sb_mont_context_t c;

    sb_fe_add(&n4, &n4, &n4); // 2n
    sb_fe_add(&n4, &n4, &n4); // 4n

    // (4n - k) * P = -k * P
    // (4n + k) * P = k * P
    // the x coordinates are the same in either case

    // test with 4n +/- 4, 4n +/- 12, 4n +/- 20, etc. Each of these values is
    // a multiple of the cofactor of the curve.

    for (size_t j = 0; j < 8; j++) {
        sb_fe_t x, x2;
        sb_fe_t k = n4;
        for (size_t i = 0; i < 4 + (j * 8); i++) {
            sb_fe_sub(&k, &k, &SB_FE_ONE);
        }
        c.x_p = *g;
        c.z_p = SB_FE_ONE;
        c.k = k;
        SB_TEST_ASSERT_SUCCESS(sb_mont_point_mult(&c, &SB_CURVE_X25519));
        x = c.x_p;

        k = n4;
        for (size_t i = 0; i < 4 + (j * 8); i++) {
            sb_fe_add(&k, &k, &SB_FE_ONE);
        }
        c.x_p = *g;
        c.z_p = SB_FE_ONE;
        c.k = k;
        SB_TEST_ASSERT_SUCCESS(sb_mont_point_mult(&c, &SB_CURVE_X25519));
        x2 = c.x_p;
        SB_TEST_ASSERT(sb_fe_equal(&x, &x2));
    }
    return 1;
}

_Bool sb_test_mont_point_mult(void)
{
    // a generator of the prime-order subgroup of curve25519
    static const sb_fe_t g = SB_FE_CONST(0, 0, 0, 0x9);

    static const sb_fe_t n =
        SB_FE_CONST(0x1000000000000000, 0x0000000000000000,
                    0x14DEF9DEA2F79CD6, 0x5812631A5CF5D3ED);

    _Bool res = 1;

    res &= test_mont_point_mult(&g, &n);

    // a generator of the prime-order subgroup of the twist of curve25519
    static const sb_fe_t g_t = SB_FE_CONST(0, 0, 0, 0x2);

    static const sb_fe_t n_t =
        SB_FE_CONST(0x1FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                    0xD6420C42BA10C653, 0x4FDB39CB4614581D);

    res &= test_mont_point_mult(&g_t, &n_t);

    return res;
}

#endif

// curve25519 private keys are 251 bits; the lowest three bits are zeroed to
// clear the cofactor, while the highest bit is cleared and bit 254 is set to
// ensure the ladder starts at a regular position.

static void
sb_mont_decode_scalar(sb_fe_t* const dest, const sb_single_t* const k,
                      const sb_mont_curve_id_t id)
{
    switch (id) {
        case SB_MONT_CURVE_25519: {
            sb_fe_from_bytes(dest, k->bytes, SB_DATA_ENDIAN_LITTLE);

            // Strip the lowest three bits to clear the cofactor
            sb_fe_set_bit(dest, 0, 0);
            sb_fe_set_bit(dest, 1, 0);
            sb_fe_set_bit(dest, 2, 0);

            // Strip the highest two bits of the scalar (well, bit 255, since
            // we're about to clobber bit 254)
            sb_fe_set_bit(dest, 255, 0);

            // Set bit 254 of the scalar
            sb_fe_set_bit(dest, 254, 1);
            break;
        }
        default: {
            SB_ASSERT(0, "Curve should have already been validated!");
            break;
        }
    }
}

static void
sb_mont_decode_point(sb_fe_t* const dest, const sb_single_t* const u,
                     const sb_mont_curve_id_t id)
{
    switch (id) {
        case SB_MONT_CURVE_25519: {
            sb_fe_from_bytes(dest, u->bytes, SB_DATA_ENDIAN_LITTLE);

            // Strip the highest bit of the point
            sb_fe_set_bit(dest, 255, 0);
            break;
        }
        default: {
            SB_ASSERT(0, "Curve should have already been validated!");
            break;
        }
    }
}

static sb_error_t sb_mont_curve_from_id(const sb_mont_curve_t** const m,
                                        const sb_mont_curve_id_t curve)
{
    switch (curve) {
        case SB_MONT_CURVE_25519: {
            *m = &SB_CURVE_X25519;
            return 0;
        }
        default: {
            *m = NULL;
            return SB_ERROR_CURVE_INVALID;
        }
    }
}

static sb_error_t sb_mont_z_regularize(sb_fe_t z[static const 1],
                                       const sb_mont_curve_t m[static const 1])
{
    sb_error_t err = SB_SUCCESS;

    // Clear bit 255 to ensure the value is < 2 * p
    sb_fe_set_bit(z, 255, 0);

    // a Z value is invalid if it is 0, since the only point with Z = 0 is the
    // point at infinity. Note that this is not expected to ever occur!
    err |= SB_ERROR_IF(DRBG_FAILURE, sb_fe_equal(z, &SB_FE_ZERO));
    err |= SB_ERROR_IF(DRBG_FAILURE, sb_fe_equal(z, &m->p->p));

    // rather than introduce bias by regularizing z, reject values which are
    // greater than unreduced. The probability of one of these values
    // occurring is infinitesimal (p < 2^-250).

    err |= SB_ERROR_IF(DRBG_FAILURE, sb_fe_lt(&m->p->p, z));
    return err;
}

sb_error_t sb_mont_shared_secret(sb_mont_context_t ctx[static const 1],
                                 sb_mont_shared_secret_t secret[static const 1],
                                 const sb_mont_private_t private[static const 1],
                                 const sb_mont_public_t public[static const 1],
                                 sb_hmac_drbg_state_t* drbg,
                                 sb_mont_curve_id_t curve)
{
    sb_error_t err = SB_SUCCESS;
    memset(ctx, 0, sizeof(sb_mont_context_t));

    const sb_mont_curve_t* m;
    err |= sb_mont_curve_from_id(&m, curve);

    if (drbg) {
        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            private->bytes, public->bytes
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            SB_ELEM_BYTES, SB_ELEM_BYTES
        };

        // The DRBG is used once, so it's not necessary to check the reseed
        // counter up front.
        err |= sb_hmac_drbg_generate_additional_vec(drbg,
                                                    ctx->buf.bytes,
                                                    SB_ELEM_BYTES,
                                                    add, add_len);
    } else {
        err |= sb_hmac_drbg_init(&ctx->drbg, private->bytes, SB_ELEM_BYTES,
                                 public->bytes, SB_ELEM_BYTES, NULL, 0);
        err |= sb_hmac_drbg_generate(&ctx->drbg, ctx->buf.bytes, SB_ELEM_BYTES);
        // This only fails due to DRBG configuration error.
        SB_ASSERT(err == 0 || err == SB_ERROR_CURVE_INVALID, "DRBG "
            "initialization and generation should never fail!");
    }

    SB_RETURN_ERRORS(err, ctx);

    sb_fe_from_bytes(&ctx->z_p, ctx->buf.bytes, SB_DATA_ENDIAN_LITTLE);
    err |= sb_mont_z_regularize(&ctx->z_p, m);
    SB_RETURN_ERRORS(err, ctx);

    sb_mont_decode_scalar(&ctx->k, private, curve);
    sb_mont_decode_point(&ctx->x_p, public, curve);

    // Modular arithmetic in Sweet B requires "quasi-reduced" inputs
    // (0 < n <= p). Input points in curve25519 are represented as integers
    // (0 <= n < 2^255).

    // Reject zero inputs; the point at infinity is not valid.
    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, sb_fe_equal(&ctx->x_p, &SB_FE_ZERO));
    SB_RETURN_ERRORS(err, ctx);

    // The input point might be unreduced. Quasi-reduce the input point.
    sb_fe_qr(&ctx->x_p, 0, m->p);

    // The point multiplication routine errors if the point is of small order.
    err |= sb_mont_point_mult(ctx, m);
    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID, (sb_fe_equal(&ctx->x_p, &m->p->p)));
    SB_ASSERT(!err, "invalid public keys should have already been caught by "
        "the scalar multiplication routine!");

    sb_fe_to_bytes(secret->bytes, &ctx->x_p, SB_DATA_ENDIAN_LITTLE);

    memset(ctx, 0, sizeof(sb_mont_context_t));
    return err;
}

sb_error_t sb_mont_compute_public_key(sb_mont_context_t ctx[static const 1],
                                      sb_mont_public_t public[static const 1],
                                      const sb_mont_private_t
                                      private[static const 1],
                                      sb_hmac_drbg_state_t* drbg,
                                      sb_mont_curve_id_t curve)
{
    // Only one curve is supported at the moment, and the invalid curve ID
    // used for testing will be caught by sb_mont_shared_secret.

    return sb_mont_shared_secret(ctx, public, private, &SB_CURVE_X25519.u,
                                 drbg, curve);
}


#ifdef SB_TEST

// This is the first value given in the iterated test procedure in RFC 7748,
// which starts off by computing a shared secret between the private scalar
// with the encoding { 0x9, 0, 0, ... } and the public key with the same
// encoding - which is the base point of the curve. As such, this is a good
// test of the compute_public_key procedure.

static const sb_mont_public_t PUB_KEY_9 = {
    {
        0x42, 0x2C, 0x8E, 0x7A, 0x62, 0x27, 0xD7, 0xBC,
        0xA1, 0x35, 0x0B, 0x3E, 0x2B, 0xB7, 0x27, 0x9F,
        0x78, 0x97, 0xB8, 0x7B, 0xB6, 0x85, 0x4B, 0x78,
        0x3C, 0x60, 0xE8, 0x03, 0x11, 0xAE, 0x30, 0x79
    }
};

static const sb_mont_private_t PRIV_KEY_9 = {{ 0x9 }};

_Bool sb_test_mont_public_key(void)
{
    sb_mont_public_t pub;
    sb_mont_context_t ctx;
    SB_TEST_ASSERT_SUCCESS(sb_mont_compute_public_key(&ctx, &pub,
                                                      &PRIV_KEY_9, NULL,
                                                      SB_MONT_CURVE_25519));
    SB_TEST_ASSERT_EQUAL(pub, PUB_KEY_9);
    return 1;
}

// RFC 7748 includes two tests without explaining the purpose behind those
// tests. One tests that the cofactor has been cleared by the scalar
// multiplication routine; the other tests that the function handles points
// on the twist correctly.

// RFC 7748, section 5.2, first test

// This point is not in the cryptographic subgroup; it is a point in the
// prime subgroup plus a point of small order.

_Bool sb_test_mont_shared_secret(void)
{
    static const sb_mont_private_t d = {
        {
            0xA5, 0x46, 0xE3, 0x6B, 0xF0, 0x52, 0x7C, 0x9D,
            0x3B, 0x16, 0x15, 0x4B, 0x82, 0x46, 0x5E, 0xDD,
            0x62, 0x14, 0x4C, 0x0A, 0xC1, 0xFC, 0x5A, 0x18,
            0x50, 0x6A, 0x22, 0x44, 0xBA, 0x44, 0x9A, 0xC4
        }};
    static const sb_mont_public_t p = {
        {
            0xE6, 0xDB, 0x68, 0x67, 0x58, 0x30, 0x30, 0xDB,
            0x35, 0x94, 0xC1, 0xA4, 0x24, 0xB1, 0x5F, 0x7C,
            0x72, 0x66, 0x24, 0xEC, 0x26, 0xB3, 0x35, 0x3B,
            0x10, 0xA9, 0x03, 0xA6, 0xD0, 0xAB, 0x1C, 0x4C
        }};
    static const sb_mont_shared_secret_t s = {
        {
            0xC3, 0xDA, 0x55, 0x37, 0x9D, 0xE9, 0xC6, 0x90,
            0x8E, 0x94, 0xEA, 0x4D, 0xF2, 0x8D, 0x08, 0x4F,
            0x32, 0xEC, 0xCF, 0x03, 0x49, 0x1C, 0x71, 0xF7,
            0x54, 0xB4, 0x07, 0x55, 0x77, 0xA2, 0x85, 0x52
        }};

    sb_mont_context_t c;
    sb_mont_shared_secret_t out;
    SB_TEST_ASSERT_SUCCESS(sb_mont_shared_secret(&c, &out, &d, &p,
                                                 NULL, SB_MONT_CURVE_25519));
    SB_TEST_ASSERT_EQUAL(out, s);
    return 1;
}

// RFC 7748, section 5.2, second test. This is a point on the twist, not on
// the actual curve25519 curve.

_Bool sb_test_mont_not_on_curve(void)
{
    static const sb_mont_private_t d = {
        {
            0x4B, 0x66, 0xE9, 0xD4, 0xD1, 0xB4, 0x67, 0x3C,
            0x5A, 0xD2, 0x26, 0x91, 0x95, 0x7D, 0x6A, 0xF5,
            0xC1, 0x1B, 0x64, 0x21, 0xE0, 0xEA, 0x01, 0xD4,
            0x2C, 0xA4, 0x16, 0x9E, 0x79, 0x18, 0xBA, 0x0D
        }};
    static const sb_mont_public_t p = {
        {
            0xE5, 0x21, 0x0F, 0x12, 0x78, 0x68, 0x11, 0xD3,
            0xF4, 0xB7, 0x95, 0x9D, 0x05, 0x38, 0xAE, 0x2C,
            0x31, 0xDB, 0xE7, 0x10, 0x6F, 0xC0, 0x3C, 0x3E,
            0xFC, 0x4C, 0xD5, 0x49, 0xC7, 0x15, 0xA4, 0x93
        }};
    static const sb_mont_public_t s = {
        {
            0x95, 0xCB, 0xDE, 0x94, 0x76, 0xE8, 0x90, 0x7D,
            0x7A, 0xAD, 0xE4, 0x5C, 0xB4, 0xB8, 0x73, 0xF8,
            0x8B, 0x59, 0x5A, 0x68, 0x79, 0x9F, 0xA1, 0x52,
            0xE6, 0xF8, 0xF7, 0x64, 0x7A, 0xAC, 0x79, 0x57
        }
    };
    sb_mont_context_t c;
    sb_mont_shared_secret_t out;
    SB_TEST_ASSERT_SUCCESS(sb_mont_shared_secret(&c, &out, &d, &p,
                                                 NULL, SB_MONT_CURVE_25519));
    SB_TEST_ASSERT_EQUAL(out, s);
    return 1;

}

// https://cr.yp.to/ecdh.html#validate gives a list of points of small order
// on curve25519. Any point which is >= 2^255 can't be decoded at all, so not
// all of these points are tested here.

// Note that the scalar multiplication routine does not explicitly check a
// list of points; rather, it multiplies by the cofactor of the curve first.

_Bool sb_test_mont_invalid_points(void)
{
    static const sb_mont_private_t d = {{ 9 }};

    // These two points have order 8.
    static const sb_mont_public_t o8_1 = {
        {
            0xE0, 0xEB, 0x7A, 0x7C, 0x3B, 0x41, 0xB8, 0xAE,
            0x16, 0x56, 0xE3, 0xFA, 0xF1, 0x9F, 0xC4, 0x6A,
            0xDA, 0x09, 0x8D, 0xEB, 0x9C, 0x32, 0xB1, 0xFD,
            0x86, 0x62, 0x05, 0x16, 0x5F, 0x49, 0xB8, 0x00
        }
    };

    static const sb_mont_public_t o8_2 = {
        {
            0x5F, 0x9C, 0x95, 0xBC, 0xA3, 0x50, 0x8C, 0x24,
            0xB1, 0xD0, 0xB1, 0x55, 0x9C, 0x83, 0xEF, 0x5B,
            0x04, 0x44, 0x5C, 0xC4, 0x58, 0x1C, 0x8E, 0x86,
            0xD8, 0x22, 0x4E, 0xDD, 0xD0, 0x9F, 0x11, 0x57
        }
    };

    // This is the point at infinity.
    static const sb_mont_public_t o1 = {{ 0 }};

    // ... and the point at infinity plus p
    static const sb_mont_public_t o1_p = {
        {
            0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        }
    };

    // This point has order 4.
    static const sb_mont_public_t o4 = {{ 1 }};

    // and the order 4 point plus p
    static const sb_mont_public_t o4_p = {
        {
            0xEE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        }
    };

    // This point has order 4 on the twist

    static const sb_mont_public_t twist_o4 = {
        {
            0xEC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        }
    };

    const sb_mont_public_t* points[] = {
        &o8_1, &o8_2, &o1, &o1_p, &o4, &o4_p, &twist_o4
    };

    sb_mont_shared_secret_t out;
    sb_mont_context_t c;

    for (size_t i = 0; i < sizeof(points) / sizeof(sb_mont_public_t*); i++) {
        SB_TEST_ASSERT_ERROR(SB_ERROR_PUBLIC_KEY_INVALID,
                             sb_mont_shared_secret(&c, &out, &d, points[i],
                                                   NULL, SB_MONT_CURVE_25519));
    }

    return 1;
}

_Bool sb_test_mont_early_errors(void)
{
    sb_hmac_drbg_state_t drbg;
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_init(&drbg, PUB_KEY_9.bytes, sizeof(PUB_KEY_9),
                          PUB_KEY_9.bytes, sizeof(PUB_KEY_9), NULL, 0)
    );
    drbg.reseed_counter = SB_HMAC_DRBG_RESEED_INTERVAL + 1;
    sb_mont_public_t pub;
    sb_mont_context_t ctx;

    SB_TEST_ASSERT_ERROR(SB_ERROR_CURVE_INVALID | SB_ERROR_RESEED_REQUIRED,
                         sb_mont_compute_public_key(&ctx, &pub, &PRIV_KEY_9,
                                                    &drbg,
                                                    SB_MONT_CURVE_INVALID));

    SB_TEST_ASSERT_ERROR(SB_ERROR_CURVE_INVALID | SB_ERROR_RESEED_REQUIRED,
                         sb_mont_shared_secret(&ctx, &pub, &PRIV_KEY_9,
                                               &PUB_KEY_9, &drbg,
                                               SB_MONT_CURVE_INVALID));
    return 1;
}

#ifdef SB_TEST_MONT_LONG
#define SB_TEST_MONT_LIMIT 1000000
#else
#define SB_TEST_MONT_LIMIT 1000
#endif

_Bool sb_test_mont_iter(void)
{
    sb_mont_context_t c;
    sb_mont_private_t k = {{ 0x9 }};
    sb_mont_private_t u = {{ 0x9 }};
    sb_mont_private_t old_k;

    size_t i = 0;
    do {
        old_k = k;
        SB_TEST_ASSERT_SUCCESS(sb_mont_shared_secret(&c, &k, &old_k, &u, NULL,
                                                     SB_MONT_CURVE_25519));
        u = old_k;
        i++;
        if (i == 1) {
            printf("1...");
            fflush(NULL);
            SB_TEST_ASSERT_EQUAL(k, PUB_KEY_9);
        } else if (i == 1000) {
            static const sb_mont_private_t res_1000 = {
                {
                    0x68, 0x4C, 0xF5, 0x9B, 0xA8, 0x33, 0x09, 0x55,
                    0x28, 0x00, 0xEF, 0x56, 0x6F, 0x2F, 0x4D, 0x3C,
                    0x1C, 0x38, 0x87, 0xC4, 0x93, 0x60, 0xE3, 0x87,
                    0x5F, 0x2E, 0xB9, 0x4D, 0x99, 0x53, 0x2C, 0x51
                }
            };
            printf("1000...");
            fflush(NULL);
            SB_TEST_ASSERT_EQUAL(k, res_1000);
        }
#if defined(SB_TEST_MONT_LONG)
        else if ((i % 10000) == 1) {
            printf(".");
            fflush(NULL);
        } else if (i == 1000000) {
            static const sb_mont_private_t res_1000000 = {
                {
                    0x7C, 0x39, 0x11, 0xE0, 0xAB, 0x25, 0x86, 0xFD,
                    0x86, 0x44, 0x97, 0x29, 0x7E, 0x57, 0x5E, 0x6F,
                    0x3B, 0xC6, 0x01, 0xC0, 0x88, 0x3C, 0x30, 0xDF,
                    0x5F, 0x4D, 0xD2, 0xD2, 0x4F, 0x66, 0x54, 0x24
                }
            };
            printf("1000000...");
            SB_TEST_ASSERT_EQUAL(k, res_1000000);
        }
#endif
    } while (i < SB_TEST_MONT_LIMIT);
    return 1;
}

#endif
