/*
 * sb_sw_lib.c: operations on short Weierstrass elliptic curves
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

#include "sb_test.h"
#include "sb_fe.h"
#include "sb_sw_lib.h"
#include "sb_sw_curves.h"
#include "sb_hmac_drbg.h"

#include <stddef.h>
#include <string.h>

// Used for point addition and conjugate addition
#define C_X1(ct) (&(ct)->c[0])
#define C_Y1(ct) (&(ct)->c[1])
#define C_X2(ct) (&(ct)->c[2])
#define C_Y2(ct) (&(ct)->c[3])
#define C_T5(ct) (&(ct)->c[4])
#define C_T6(ct) (&(ct)->c[5])
#define C_T7(ct) (&(ct)->c[6])
#define C_T8(ct) (&(ct)->c[7])

// The scalar used for point multiplication
#define MULT_K(ct) (&(ct)->h[0])

// The initial Z value, and the current Z coordinate in multiplication-addition
#define MULT_Z(ct) (&(ct)->h[1])

// The point to be multiplied, for shared secret generation and signature
// verification
#define MULT_POINT(ct) (&(ct)->h[2]) // 2 and 3

// The message to be signed as a scalar
#define SIGN_MESSAGE(ct) (&(ct)->h[2])

// The private key used in signing as a scalar (K is the signature k)
#define SIGN_PRIVATE(ct) (&(ct)->h[3])

// The scalar to multiply the base point by in signature verification
#define MULT_ADD_KG(ct) (&(ct)->c[8])

// Stores P + G in signature verification
#define MULT_ADD_PG(ct) (&(ct)->c[9]) // 9 and 10

// The message to be verified as a scalar
#define VERIFY_MESSAGE(ct) (&(ct)->c[9])

// The two working components of the signature, R and S
#define VERIFY_QS(ct) (&(ct)->c[10])
#define VERIFY_QR(ct) (&(ct)->c[11])

// All multiplication in Sweet B takes place using Montgomery multiplication
// MM(x, y) = x * y * R^-1 mod M where R = 2^SB_FE_BITS
// This has the nice property that MM(x * R, y * R) = x * y * R
// which means that sequences of operations can be chained together

// The inner loop of the Montgomery ladder takes place with coordinates that have been
// pre-multiplied by R. Point addition involves no constants, only additions, subtractions,
// and multiplications (and squarings). As such, the factor of R in coordinates is maintained
// throughout: mont_mult(a * R, b * R) = (a * b) * R, a * R + b * R = (a + b) * R, etc.
// For simplicity, the factor R will be ignored in the following comments.

// Initial point doubling: compute 2P in Jacobian coordinates from P in
// affine coordinates.

// Algorithm 23 from Rivain 2011, modified slightly

// Input:  P = (x2, y2) in affine coordinates
// Output: (x1, y1) = P', (x2, y2) = 2P in co-Z with t5 = Z = 2 * y2
// Cost:   6MM + 11A
static void sb_sw_point_initial_double(sb_sw_context_t c[static const 1],
                                       const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_double(C_T5(c), C_Y2(c), s->p); // t5 = Z
    sb_fe_mont_square(C_Y1(c), C_X2(c), s->p); // t2 = x^2
    sb_fe_mod_sub(C_Y1(c), C_Y1(c), s->minus_a_r_over_three,
                  s->p); // t2 = x^2 + a / 3
    sb_fe_mod_double(C_X1(c), C_Y1(c), s->p); // t1 = 2 * (x^2 + a / 3)
    sb_fe_mod_add(C_Y1(c), C_Y1(c), C_X1(c),
                  s->p); // t2 = (3 * x^2 + a) = B

    sb_fe_mont_square(C_T6(c), C_Y2(c), s->p); // t6 = y^2
    sb_fe_mod_double(C_Y2(c), C_T6(c), s->p); // t4 = 2 * y^2
    sb_fe_mod_double(C_T6(c), C_Y2(c), s->p); // t6 = 4 * y^2
    sb_fe_mont_mult(C_X1(c), C_X2(c), C_T6(c),
                    s->p); // t1 = 4 * x * y^2 = A

    sb_fe_mont_square(C_X2(c), C_Y1(c),
                      s->p); // t3 = B^2

    sb_fe_mod_sub(C_X2(c), C_X2(c), C_X1(c), s->p); // t2 = B^2 - A
    sb_fe_mod_sub(C_X2(c), C_X2(c), C_X1(c),
                  s->p); // x2 = B^2 - 2 * A = X2

    sb_fe_mod_sub(C_T6(c), C_X1(c), C_X2(c), s->p); // t6 = A - X2
    sb_fe_mont_mult(C_T7(c), C_Y1(c), C_T6(c),
                    s->p); // t7 = B * (A - X2)

    sb_fe_mont_square(C_Y1(c), C_Y2(c),
                      s->p); // t2 = (2 * y^2)^2 = 4 * y^4
    sb_fe_mod_double(C_Y1(c), C_Y1(c), s->p); // Y1 = 8 * y^4 = Z^3 * y
    sb_fe_mod_sub(C_Y2(c), C_T7(c), C_Y1(c),
                  s->p); // Y2 = B * (A - X2) - Y1
}

// Co-Z point addition with update:
// Input: P = (x1, y1), Q = (x2, y2) in co-Z, with x2 - x1 in t6
// Output: P + Q = (x3, y3) in (x1, y1), P = (x1', y1') in (x2, y2)
//         B + C = t5 with Z' = Z * (x2 - x1)
//     or: P = P + Q, Q = P'
// Uses:   t5, t6, t7; leaves t8 unmodified (used by conjugate addition and Z recovery)
// Cost:   6MM + 6A
static void sb_sw_point_co_z_add_update_zup(sb_sw_context_t c[static const 1],
                                            const sb_sw_curve_t s[static const 1])
{
    sb_fe_mont_square(C_T5(c), C_T6(c),
                      s->p); // t5 = (x2 - x1)^2 = (Z' / Z)^2 = A
    sb_fe_mont_mult(C_T6(c), C_X2(c), C_T5(c), s->p); // t6 = x2 * A = C
    sb_fe_mont_mult(C_X2(c), C_X1(c), C_T5(c), s->p); // t3 = x1 * A = B = x1'
    sb_fe_mod_sub(C_T7(c), C_Y2(c), C_Y1(c), s->p); // t7 = y2 - y1
    sb_fe_mod_add(C_T5(c), C_X2(c), C_T6(c), s->p); // t5 = B + C
    sb_fe_mod_sub(C_T6(c), C_T6(c), C_X2(c),
                  s->p); // t6 = C - B = (x2 - x1)^3 = (Z' / Z)^3
    sb_fe_mont_mult(C_Y2(c), C_Y1(c), C_T6(c),
                    s->p); // y1' = y1 * (Z' / Z)^3 = E
    sb_fe_mont_square(C_X1(c), C_T7(c), s->p); // t1 = (y2 - y1)^2 = D
    sb_fe_mod_sub(C_X1(c), C_X1(c), C_T5(c), s->p); // x3 = D - B - C
    sb_fe_mod_sub(C_T6(c), C_X2(c), C_X1(c), s->p); // t6 = B - x3
    sb_fe_mont_mult(C_Y1(c), C_T7(c), C_T6(c),
                    s->p); // t4 = (y2 - y1) * (B - x3)
    sb_fe_mod_sub(C_Y1(c), C_Y1(c), C_Y2(c),
                  s->p); // y3 = (y2 - y1) * (B - x3) - E
}

// Co-Z addition with update, with Z-update computation
// Sets t6 to x2 - x1 before calling sb_sw_point_co_z_add_update_zup
// Cost: 6MM + 7A
static inline void
sb_sw_point_co_z_add_update(sb_sw_context_t c[static const 1],
                            const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_sub(C_T6(c), C_X2(c), C_X1(c), s->p); // t6 = x2 - x1 = Z' / Z
    sb_sw_point_co_z_add_update_zup(c, s);
}

// Co-Z conjugate addition with update, with Z-update computation
// Input:  P = (x1, y1), Q = (x2, y2) in co-Z, with x2 - x1 in t6
// Output: P + Q = (x3, y3) in (x1, y1), P - Q = in (x2, y2), P' in (t6, t7)
//         with Z' = Z * (x2 - x1)
//     or: P = P + Q, Q = P - Q
// Uses:   t5, t6, t7, t8
// Cost:   8MM + 11A (6MM + 7A for addition-with-update + 2MM + 4A)
static void sb_sw_point_co_z_conj_add(sb_sw_context_t c[static const 1],
                                      const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_add(C_T8(c), C_Y1(c), C_Y2(c), s->p); // t8 = y1 + y2

    sb_sw_point_co_z_add_update(c, s); // t5 = B + C

    *C_T6(c) = *C_X2(c);
    *C_T7(c) = *C_Y2(c);

    sb_fe_mont_square(C_X2(c), C_T8(c), s->p); // t6 = (y1 + y2)^2 = F
    sb_fe_mod_sub(C_X2(c), C_X2(c), C_T5(c), s->p); // t6 = F - (B + C) = x3'

    sb_fe_mod_sub(C_T5(c), C_X2(c), C_T6(c), s->p); // t5 = x3' - B
    sb_fe_mont_mult(C_Y2(c), C_T8(c), C_T5(c),
                    s->p); // t2 = (y2 + y1) * (x3' - B)
    sb_fe_mod_sub(C_Y2(c), C_Y2(c), C_T7(c),
                  s->p); // y3' = (y2 + y1) * (x3' - B) - E
}

// Regularize the bit count of the scalar by adding CURVE_N or 2 * CURVE_N
// The resulting scalar will have P256_BITS + 1 bits, with the highest bit set
// This enables the Montgomery ladder to start at (1P, 2P) instead of (0P, 1P).
// The resulting scalar k is always >= N + R (where R is 2^256 mod N) and
// < 2N + R.
// To see how this works, consider an input scalar of R: the first addition
// produces N + (2^256 - N) = 2^256 and overflows; therefore the resulting
// scalar will be N + R, and this is the lowest scalar that produces
// overflow on the first addition. Now consider an input scalar of R - 1:
// the first addition produces N + (2^256 - N - 1) = 2^256 - 1 which does
// not overflow; hence a second addition is necessary. This is the largest
// scalar which requires two additions.

static void sb_sw_regularize_scalar(sb_fe_t scalar[static const 1],
                                    sb_sw_context_t c[static const 1],
                                    const sb_sw_curve_t s[static const 1])
{
    const sb_word_t c_1 = sb_fe_add(C_T5(c), scalar, &s->n->p);
    sb_fe_add(scalar, C_T5(c), &s->n->p);
    sb_fe_ctswap(c_1, scalar, C_T5(c));
}


static void
sb_sw_point_mult(sb_sw_context_t m[static const 1],
                 const sb_fe_t point[static const 2],
                 const sb_sw_curve_t s[static const 1])
{
    // Input scalars MUST always be checked for validity
    // (k is reduced and ∉ {-2, -1, 0, 1} mod N).

    sb_sw_regularize_scalar(MULT_K(m), m, s);

    // Throughout the ladder, (x1, y1) is (X0 * R, Y0 * R)
    // (x2, y2) is (X1 * R, Y1 * R)
    // This enables montgomery multiplies to be used in the ladder without
    // explicit multiplies by R^2 mod P

    *C_X2(m) = point[0];
    *C_Y2(m) = point[1];

    sb_sw_point_initial_double(m, s);

    // The following applies a Z update of iz * R^-1.

    sb_fe_mont_square(C_T7(m), MULT_Z(m), s->p); // t7 = z^2
    sb_fe_mont_mult(C_T6(m), MULT_Z(m), C_T7(m), s->p); // t6 = z^3

    *C_T5(m) = *C_X1(m);
    sb_fe_mont_mult(C_X1(m), C_T5(m), C_T7(m), s->p); // x z^2
    *C_T5(m) = *C_Y1(m);
    sb_fe_mont_mult(C_Y1(m), C_T5(m), C_T6(m), s->p); // y z^3
    *C_T5(m) = *C_X2(m);
    sb_fe_mont_mult(C_X2(m), C_T5(m), C_T7(m), s->p); // x z^2
    *C_T5(m) = *C_Y2(m);
    sb_fe_mont_mult(C_Y2(m), C_T5(m), C_T6(m), s->p); // y z^3

    // (x1 * R^-1, y1 * R^-1) = R0, (x2 * R^-1, y2 * R^-1) = R1
    // R1 - R0 = P' for some Z

    // To show that the ladder is complete for scalars ∉ {-2, -1, 0, 1}, let P = p * G
    // R1 = 2 * p * G
    // R0 = p * G
    // It is easy to see that in a prime-order group, neither R1 nor R0 is
    // the point at infinity at the beginning of the algorithm assuming nonzero p.
    // In other words, every point on the curve is a generator.

    // Through the ladder, at the end of each ladder step, we have:
    // R0 = k[256..i] * P
    // R1 = R0 + P
    // where k[256..i] is the 256th through i_th bit of `k` inclusive
    // The beginning of the loop is the end of the first ladder step (i = 256).

    // Each ladder step computes the sum of R0 and R1, and one point doubling.
    // The point doubling formula does not have exceptional cases, so we must
    // consider point additions by zero and inadvertent point doublings.
    // (Additions of -P and P would produce zero, which reduces to the case
    // of addition by zero.) Point doublings do not occur simply because R0 +
    // (R0 + P) is never a doubling operation.

    // R0 = k[256..i] * P is the point at infinity if k[256..i] is zero.
    // k[256] is 1 and N is 256 bits long. Therefore, k[256..i] is nonzero
    // and less than N for all i > 1.
    // It remains to consider the case of k[256..1] = N and
    // k[256..0] = 2N. If k[256..1] is N, then k[256..0] is 2N or 2N + 1.
    // Because the original input scalar was reduced, this only occurs with
    // an input scalar of 0 or 1.

    // R1 = (k[256..i] + 1) * P is zero if k[256..i] + 1 is zero.
    // N is 256 bits long. For i > 1, k[256..i] is at most 255 bits long and therefore
    // less than N - 1. It remains to consider k[256..1] = N - 1 and k[256..0] = 2N - 1.
    // If k[256..1] is N - 1, then k[256..0] is 2N - 2 or 2N - 1.
    // Because the input scalar was reduced, this only occurs with an input
    // scalar of -2 or -1.

    // The following intermediaries are generated:
    // (2 * k[256..i] + 1) * P, P, and -P

    // Because the order of the group is prime, it is easy to see that
    // k[256..i] * P = 0 iff k[256..i] is 0 for nonzero p.
    // What about (2 * k[256..i] + 1) * P?
    // 2 * k[256..i] + 1 must be zero.
    // For i > 2, 2 * k[256..i] is at most 255 bits long and thus
    // less than N - 1. It remains to consider 2 * k[256..2] = N - 1,
    // 2 * k[256..1] = N - 1, and 2 * k[256..0] = N - 1.

    // If 2 * k[256..2] = N - 1, then k[256..2] = (N - 1) / 2.
    // k[256..1] is then N - 1 or N, and k[256..0] is 2N - 2, 2N - 1, N, or N + 1.
    // Thus, this occurs only if k ∈ { -2, -1, 0, 1 }.

    // If 2 * k[256..1] = N - 1, then k[256..1] is (N - 1) / 2.
    // k[256..0] is then N - 1 or N, which only occurs if k ∈ { -1, 0 }.

    // Thus, for reduced inputs ∉ {-2, -1, 0, 1} the Montgomery ladder
    // is non-exceptional for our short Weierstrass curves.

    // 14MM + 18A per bit
    // c.f. Table 1 in Rivain 2011 showing 9M + 5S + 18A

    sb_word_t swap = 0;

    for (size_t i = SB_FE_BITS - 1; i > 0; i--) {
        const sb_word_t b = sb_fe_test_bit(MULT_K(m), i);

        // if swap is 0: (x2, y2) = R0; (x1, y1) = R1
        // if swap is 1: (x2, y2) = R1; (x1, y1) = R0

        // swap iff bit is set:
        // (x1, y1) = R_b; (x2, y2) = R_{1-b}
        swap ^= b;
        sb_fe_ctswap(swap, C_X1(m), C_X2(m));
        sb_fe_ctswap(swap, C_Y1(m), C_Y2(m));
        swap = b;

        // our scalar 'k' is a 257-bit integer
        // R0 = k[256..(i+1)] * P
        // at the beginning of the loop, when i is 255:
        // R0 = k[256..256] * P = 1 * P
        // R1 = R0 + P = (k[256..(i+1)] + 1) * P


        // When k[i] is 0:
        // (x1, y1) = k[256..(i+1)] * P
        // (x2, y2) = (k[256..(i+1)] + 1) * P

        // When k[i] is 1:
        // (x1, y1) = (k[256..(i+1)] + 1) * P
        // (x2, y2) = k[256..(i+1)] * P

        // R_b = R_b + R_{1-b}; R_{1-b} = R_{b} - R{1-b}
        sb_sw_point_co_z_conj_add(m, s); // 6MM + 7A

        // (x1, y1) = (2 * k[256..(i+1)] + 1 ) * P

        // if k[i] is 0:
        // (x2, y2) = -1 * P

        // if k[i] is 1:
        // (x2, y2) = 1 * P

        // R_b = R_b + R_{1-b}; R_{1-b} = R_b'
        sb_sw_point_co_z_add_update(m, s); // 8MM + 11A

        // if k[i] is 0:
        // (x1, y1) is 2 * k[256..(i+1)] * P = k[256..i] * P
        // (x2, y2) is (2 * k[256..(i+1)] + 1 ) * P = (k[256..i] + 1) * P

        // if k[i] is 1:
        // (x1, y1) is (2 * k[256..(i+1)] + 2) * P = (k[256..i] + 1) * P
        // (x2, y2) is (2 * k[256..(i+1)] + 1 ) * P = k[256..i] * P

        // R_swap is k[256..i] * P
        // R_!swap is (k[256..i] + 1) * P
    }

    const sb_word_t b = sb_fe_test_bit(MULT_K(m), 0);

    // (x1, y1) = R0; (x2, y2) = R1

    // swap iff bit is set:
    swap ^= b;
    sb_fe_ctswap(swap, C_X1(m), C_X2(m));
    sb_fe_ctswap(swap, C_Y1(m), C_Y2(m));

    // (x1, y1) = R_b; (x2, y2) = R_{1-b}

    // here the logical meaning of the registers swaps!
    sb_sw_point_co_z_conj_add(m, s);
    // (x1, y1) = R_{1-b}, (x2, y2) = R_b

    // if b is 1, swap the registers
    sb_fe_ctswap(b, C_X1(m), C_X2(m));
    sb_fe_ctswap(b, C_Y1(m), C_Y2(m));
    // (x1, y1) = R1; (x2, y2) = R0

    // Compute final Z^-1
    sb_fe_mod_sub(C_T8(m), C_X1(m), C_X2(m), s->p); // X1 - X0

    // if b is 1, swap the registers back
    sb_fe_ctswap(b, C_X1(m), C_X2(m));
    sb_fe_ctswap(b, C_Y1(m), C_Y2(m));
    // (x1, y1) = R_{1-b}, (x2, y2) = R_b

    sb_fe_mont_mult(C_T5(m), C_T8(m), C_Y2(m), s->p);
    // t5 = Y_b * (X_1 - X_0)

    sb_fe_mont_mult(C_T8(m), C_T5(m), &point[0], s->p);
    // t8 = t5 * x_P = x_P * Y_b * (X_1 - X_0)

    sb_fe_mod_inv_r(C_T8(m), C_T5(m), C_T6(m), s->p);
    // t8 = 1 / (x_P * Y_b * (X_1 - X_0))

    sb_fe_mont_mult(C_T5(m), C_T8(m), &point[1], s->p);
    // t5 = yP / (x_P * Y_b * (X_1 - X_0))

    sb_fe_mont_mult(C_T8(m), C_T5(m), C_X2(m), s->p);
    // t8 = (X_b * y_P) / (x_P * Y_b * (X_1 - X_0))
    // = final Z^-1

    // (x1, y1) = R_{1-b}, (x2, y2) = R_b
    sb_sw_point_co_z_add_update(m, s);
    // the logical meaning of the registers is reversed
    // (x1, y1) = R_b, (x2, y2) = R_{1-b}

    // if b is 0, swap the registers
    sb_fe_ctswap((b ^ (sb_word_t) 1), C_X1(m), C_X2(m));
    sb_fe_ctswap((b ^ (sb_word_t) 1), C_Y1(m), C_Y2(m));
    // (x1, y1) = R1; (x2, y2) = R0

    // t8 = Z^-1 * R
    // x2 = X0 * Z^2 * R
    // y2 = Y0 * Z^3 * R

    sb_fe_mont_square(C_T5(m), C_T8(m), s->p); // t5 = Z^-2 * R
    sb_fe_mont_mult(C_T6(m), C_T5(m), C_T8(m), s->p); // t6 = Z^-3 * R

    sb_fe_mont_mult(C_T7(m), C_T5(m), C_X2(m), s->p); // t7 = X0 * Z^-2 * R
    sb_fe_mont_reduce(C_X1(m), C_T7(m), s->p); // Montgomery reduce to x1

    sb_fe_mont_mult(C_T7(m), C_T6(m), C_Y2(m), s->p); // t7 = Y0 * Z^-3 * R
    sb_fe_mont_reduce(C_Y1(m), C_T7(m), s->p); // Montgomery reduce to y1

    sb_fe_sub(MULT_K(m), MULT_K(m), &s->n->p); // subtract off the overflow
    sb_fe_mod_sub(MULT_K(m), MULT_K(m), &s->n->p,
                  s->n);  // reduce to restore original scalar
}

// Multiplication-addition using Shamir's trick to produce k_1 * P + k_2 * Q

// sb_sw_point_mult_add_z_update computes the new Z and then performs co-Z
// point addition at a cost of 7MM + 7A
static void sb_sw_point_mult_add_z_update(sb_sw_context_t q[static const 1],
                                          const sb_sw_curve_t s[static const 1])
{
    sb_fe_mod_sub(C_T6(q), C_X2(q), C_X1(q), s->p); // t6 = x2 - x1 = Z' / Z
    sb_fe_mont_mult(C_T5(q), C_T6(q), MULT_Z(q), s->p); // updated Z
    *MULT_Z(q) = *C_T5(q);

    sb_sw_point_co_z_add_update_zup(q, s);
}

// sb_sw_point_mult_add_apply_z applies a Z value to the selected point
// (H, P + H, G + H, or P + G + H) at a cost of 4MM
static void sb_sw_point_mult_add_apply_z(sb_sw_context_t q[static const 1],
                                         const sb_sw_curve_t s[static const 1])
{
    sb_fe_mont_square(C_T6(q), MULT_Z(q), s->p); // Z^2

    sb_fe_mont_mult(C_T7(q), C_X2(q), C_T6(q), s->p);
    *C_X2(q) = *C_T7(q);

    sb_fe_mont_mult(C_T7(q), C_T6(q), MULT_Z(q), s->p); // Z^3
    sb_fe_mont_mult(C_T6(q), C_Y2(q), C_T7(q), s->p);
    *C_Y2(q) = *C_T6(q);
}

// sb_sw_point_mult_add_select selects the point to conjugate-add to the
// running total based on the bits of the given input scalars
static void sb_sw_point_mult_add_select(const sb_word_t bp, const sb_word_t bg,
                                        sb_sw_context_t q[static const 1],
                                        const sb_sw_curve_t s[static const 1])
{
    // select a point S for conjugate addition with R
    // if bp = 0 and bg = 0, select h
    // if bp = 0 and bg = 1, select g + h
    // if bp = 1 and bg = 0, select p + h
    // if bp = 1 and bg = 1, select p + g + h
    *C_X2(q) = s->h_r[0];
    *C_Y2(q) = s->h_r[1];

    *C_T5(q) = s->g_h_r[0];
    *C_T6(q) = s->g_h_r[1];
    sb_fe_ctswap(bg, C_X2(q), C_T5(q));
    sb_fe_ctswap(bg, C_Y2(q), C_T6(q));

    *C_T5(q) = MULT_POINT(q)[0];
    *C_T6(q) = MULT_POINT(q)[1];
    sb_fe_ctswap(bp, C_X2(q), C_T5(q));
    sb_fe_ctswap(bp, C_Y2(q), C_T6(q));

    *C_T5(q) = MULT_ADD_PG(q)[0];
    *C_T6(q) = MULT_ADD_PG(q)[1];
    sb_fe_ctswap(bp & bg, C_X2(q), C_T5(q));
    sb_fe_ctswap(bp & bg, C_Y2(q), C_T6(q));

    sb_sw_point_mult_add_apply_z(q, s);
}

// Signature verification uses a regular double-and-add algorithm with Shamir's
// trick for dual scalar-basepoint multiplication. Because adding O (the
// point at infinity) is an exceptional case in the standard formulae for
// point addition on short Weierstrass curves, each iteration adds an
// additional point H. Due to regularization of the input scalars,
// the algorithm starts with bit 256 in both k_p and k_g set, so the initial
// value is P + G + H, and at the end of the loop, (2^257 - 1) * H has been
// added, producing k_p * P + k_g * G + (2^257 - 1) * H. To correct for this,
// one could subtract the extra multiple of H at the end of the algorithm,
// but instead H has been chosen so that we can easily adjust k_g before the
// multiplication instead. Let H be (2^257 - 1)^-1 * G. Then compute:
//   k_p * P + (k_g - 1) * G + (2^257 - 1) * H
// = k_p * P + (k_g - 1) * G + (2^257 - 1) * (2^257 - 1)^-1 * G
// = k_p * P + (k_g - 1) * G + G
// = k_p * P + k_g * G

// The algorithm is as follows:

// Given inputs k_p, P, k_g on some curve with base point G, and let H as
// above, with G + H precomputed

// 1. Compute P + H and P + G + H

// Let S(b_p, b_g) be:         H if b_p == 0 && b_g == 0
//                         P + H if b_p == 1 && b_g == 0
//                         G + H if b_p == 0 && b_g == 1
//                     P + G + H if b_p == 1 && b_g == 1

// 2. k_g := k_g - 1
// 3. k_p := regularize(k_p)
// 4. k_g := regularize(k_g)
// 5. R := P + G + H
// 6. R := 2 * R
// 7. R := R + S(k_p_255, k_g_255)
// 8. for i from 254 downto 0:
//    8.1. R' := R + S(k_p_i, k_g_i)
//    8.2. R  := R + R'
// 9. return R

// Produces kp * P + kg * G in (x1, y1) with Z * R in t5
static void sb_sw_point_mult_add_z(sb_sw_context_t q[static const 1],
                                   const sb_sw_curve_t s[static const 1])
{
    sb_fe_t* const kp = MULT_K(q);
    sb_fe_t* const kg = MULT_ADD_KG(q);

    // Subtract one from kg to account for the addition of (2^257 - 1) * H = G
    sb_fe_sub(kg, kg, &SB_FE_ONE);

    // Regularize the input scalars so the ladder starts at P + G + H
    sb_sw_regularize_scalar(kp, q, s);
    sb_sw_regularize_scalar(kg, q, s);

    // multiply (x, y) of P by R
    sb_fe_mont_mult(C_X1(q), &MULT_POINT(q)[0], &s->p->r2_mod_p, s->p);
    MULT_POINT(q)[0] = *C_X1(q);
    sb_fe_mont_mult(C_Y1(q), &MULT_POINT(q)[1], &s->p->r2_mod_p, s->p);
    MULT_POINT(q)[1] = *C_Y1(q);

    *C_X2(q) = s->h_r[0];
    *C_Y2(q) = s->h_r[1];

    // Save initial Z in T8 until it can be applied
    *C_T8(q) = *MULT_Z(q);

    // P and H are in affine coordinates, so our current Z is one (R in
    // Montgomery domain)
    *MULT_Z(q) = s->p->r_mod_p;

    // (x1, x2) = P + H; (x2, y2) = P'
    sb_sw_point_mult_add_z_update(q, s);

    // Apply Z to G before co-Z addition of (P + H) and G
    *C_X2(q) = s->g_r[0];
    *C_Y2(q) = s->g_r[1];
    sb_sw_point_mult_add_apply_z(q, s);

    // (x1, x2) = P + G + H; (x2, y2) = P + H
    sb_sw_point_mult_add_z_update(q, s);

    // Invert Z and multiply so that P + H and P + G + H are in affine
    // coordinates
    *C_T5(q) = *MULT_Z(q); // t5 = Z * R
    sb_fe_mod_inv_r(C_T5(q), C_T6(q), C_T7(q), s->p); // t5 = Z^-1 * R
    sb_fe_mont_square(C_T6(q), C_T5(q), s->p); // t6 = Z^-2 * R
    sb_fe_mont_mult(C_T7(q), C_T5(q), C_T6(q), s->p); // t7 = Z^-3 * R

    // Apply Z to P + H
    sb_fe_mont_mult(&MULT_POINT(q)[0], C_X2(q), C_T6(q), s->p);
    sb_fe_mont_mult(&MULT_POINT(q)[1], C_Y2(q), C_T7(q), s->p);

    // Apply Z to P + G + H
    sb_fe_mont_mult(&MULT_ADD_PG(q)[0], C_X1(q), C_T6(q), s->p);
    sb_fe_mont_mult(&MULT_ADD_PG(q)[1], C_Y1(q), C_T7(q), s->p);

    // Computation begins with R = P + G + H due to regularization of the
    // scalars. If bit 255 of kp and kpg are both 1, this would lead to a
    // point doubling!
    // Avoid the inadvertent doubling in the first bit, so that the regular
    // ladder can start at 2 * (P + G + H) + S

    *C_X2(q) = MULT_ADD_PG(q)[0];
    *C_Y2(q) = MULT_ADD_PG(q)[1];

    sb_sw_point_initial_double(q, s);
    // 2 * (P + G + H) is now in (x2, y2); Z is in t5

    // apply initial Z
    *MULT_Z(q) = *C_T8(q);
    sb_sw_point_mult_add_apply_z(q, s);

    // z coordinate of (x2, y2) is now iz * t5
    sb_fe_mont_mult(C_T6(q), MULT_Z(q), C_T5(q), s->p);
    *MULT_Z(q) = *C_T6(q);

    // move 2 * (P + G + H) to (x1, y1)
    *C_X1(q) = *C_X2(q);
    *C_Y1(q) = *C_Y2(q);

    // 14MM + 14A + 4MM co-Z update = 18MM + 14A per bit
    // Note that mixed Jacobian-affine doubling-addition can be done in 18MM.
    // Assuming a Hamming weight of ~128 on both scalars and 8MM doubling, the
    // expected performance of a conditional Jacobian double-and-add
    // implementation would be (3/4 * 18MM) + (1/4 * 8MM) = 15.5MM/bit

    // The algorithm used here is regular and reuses the existing co-Z addition
    // operation. Conventional wisdom says that signature verification does
    // not need to be constant time; however, it's not clear to me that this
    // holds in all cases. For instance, an embedded system might leak
    // information about its firmware version by the amount of time that it
    // takes to verify a signature on boot.

    // If you want a variable-time ladder, consider using Algorithms 14 and
    // 17 from Rivain 2011 instead.

    // Note that this algorithm may also not be SPA- or DPA-resistant, as H,
    // P + H, G + H, and P + G + H are stored and used in affine coordinates,
    // so the co-Z update of these variables might be detectable even with
    // Z blinding. If this matters for signature verification in your
    // application, please contact the authors for commercial support.

    for (size_t i = SB_FE_BITS - 1; i < SB_FE_BITS; i--) {
        const sb_word_t bp = sb_fe_test_bit(kp, i);
        const sb_word_t bg = sb_fe_test_bit(kg, i);

        sb_sw_point_mult_add_select(bp, bg, q, s);

        // (x1, y1) = (R + S), (x2, y2) = R'
        sb_sw_point_mult_add_z_update(q, s);

        // The initial point has already been doubled
        if (i < SB_FE_BITS - 1) {
            // R := (R + S) + R = 2 * R + S
            sb_sw_point_mult_add_z_update(q, s);
        }
    }

    *C_T6(q) = *C_X1(q);
    sb_fe_mont_reduce(C_X1(q), C_T6(q), s->p);
    *C_T6(q) = *C_Y1(q);
    sb_fe_mont_reduce(C_Y1(q), C_T6(q), s->p);
    *C_T5(q) = *MULT_Z(q);
}

#ifdef SB_TEST

// Test that A * (B * G) + C * G = (A * B + C) * G
static _Bool test_sw_point_mult_add(const sb_fe_t* const ka,
                                    const sb_fe_t* const kb,
                                    const sb_fe_t* const kc,
                                    const sb_sw_curve_t* const s)
{
    sb_sw_context_t m;
    memset(&m, 0, sizeof(m));

    sb_fe_t kabc;

    sb_fe_mont_mult(C_T5(&m), ka, kb, s->n);
    sb_fe_mont_mult(&kabc, C_T5(&m), &s->n->r2_mod_p, s->n);
    sb_fe_mod_add(&kabc, &kabc, kc, s->n);

    *MULT_Z(&m) = SB_FE_ONE;

    *MULT_K(&m) = *kb;
    sb_sw_point_mult(&m, s->g_r, s);

    sb_fe_t pb[] = { *C_X1(&m), *C_Y1(&m) };

    *MULT_K(&m) = kabc;
    sb_sw_point_mult(&m, s->g_r, s);

    sb_fe_t pabc[] = { *C_X1(&m), *C_Y1(&m) };

    sb_sw_context_t q;
    memset(&q, 0, sizeof(q));
    *MULT_Z(&q) = SB_FE_ONE;

    MULT_POINT(&q)[0] = pb[0];
    MULT_POINT(&q)[1] = pb[1];
    *MULT_K(&q) = *ka;
    *MULT_ADD_KG(&q) = *kc;

    // A * (B * G) + C * G = (A * B + C) * G
    sb_sw_point_mult_add_z(&q, s);

    // put pabc in co-Z with the result
    sb_fe_mont_square(C_T6(&q), C_T5(&q), s->p); // t6 = Z^2 * R
    sb_fe_mont_mult(C_T7(&q), C_T6(&q), C_T5(&q), s->p); // t7 = Z^3 * R

    sb_fe_mont_mult(C_X2(&q), C_T6(&q), &pabc[0], s->p); // x2 = x * Z^2
    sb_fe_mont_mult(C_Y2(&q), C_T7(&q), &pabc[1], s->p); // y2 = y * Z^3
    SB_TEST_ASSERT(
        sb_fe_equal(C_X1(&q), C_X2(&q)) && sb_fe_equal(C_Y1(&q), C_Y2(&q)));
    return 1;
}

static _Bool generate_fe(sb_fe_t* const fe, sb_hmac_drbg_state_t* const drbg)
{
    sb_single_t s;
    SB_TEST_ASSERT_SUCCESS(sb_hmac_drbg_generate(drbg, s.bytes, SB_ELEM_BYTES));
    sb_fe_from_bytes(fe, s.bytes, SB_DATA_ENDIAN_BIG);
    return 1;
}

_Bool sb_test_sw_point_mult_add(void)
{
    sb_fe_t ka = SB_FE_CONST(0, 0, 0, 3);
    sb_fe_t kb = SB_FE_CONST(0, 0, 0, 4);
    sb_fe_t kc = SB_FE_CONST(0, 0, 0, 6);
    SB_TEST_ASSERT(test_sw_point_mult_add(&ka, &kb, &kc, &SB_CURVE_P256));
    SB_TEST_ASSERT(test_sw_point_mult_add(&ka, &kb, &kc, &SB_CURVE_SECP256K1));
    return 1;
}

_Bool sb_test_sw_point_mult_add_rand(void)
{
    sb_fe_t ka, kb, kc;
    sb_hmac_drbg_state_t drbg;
    memset(&drbg, 0, sizeof(drbg));

    for (size_t i = 0; i < 64; i++) {
        SB_TEST_ASSERT(generate_fe(&ka, &drbg));
        SB_TEST_ASSERT(generate_fe(&kb, &drbg));
        SB_TEST_ASSERT(generate_fe(&kc, &drbg));
        SB_TEST_ASSERT(test_sw_point_mult_add(&ka, &kb, &kc, &SB_CURVE_P256));
        SB_TEST_ASSERT(
            test_sw_point_mult_add(&ka, &kb, &kc, &SB_CURVE_SECP256K1));
        drbg.reseed_counter = 1;
    }
    return 1;
}

#endif

// Given a point context with x in *C_X1(c), computes
// y^2 = x^3 + a * x + b in *C_Y1(c)
static void sb_sw_curve_y2(sb_sw_context_t c[static const 1],
                           const sb_sw_curve_t s[static const 1])
{
    sb_fe_mont_mult(C_T5(c), C_X1(c), &s->p->r2_mod_p, s->p); // t5 = x * R
    sb_fe_mont_mult(C_T6(c), C_T5(c), C_X1(c), s->p); // t6 = x^2
    sb_fe_mod_sub(C_T6(c), C_T6(c), &s->minus_a, s->p); // t6 = x^2 + a
    sb_fe_mont_mult(C_Y1(c), C_T5(c), C_T6(c),
                    s->p); // y1 = (x^2 + a) * x * R * R^-1 = x^3 + a * x
    sb_fe_mod_add(C_Y1(c), C_Y1(c), &s->b, s->p); // y1 = y^2 = x^3 + a * x + b
}

// Note that this assumes reduced input, not quasi-reduced input!
static _Bool
sb_sw_point_valid(const sb_fe_t point[static const 2],
                  sb_sw_context_t c[static const 1],
                  const sb_sw_curve_t s[static const 1])
{
    // The point at infinity is not valid.
    if (sb_fe_equal(&point[0], &SB_FE_ZERO) &&
        sb_fe_equal(&point[1], &SB_FE_ZERO)) {
        return 0;
    }

    // Unreduced points are not valid.
    if (!(sb_fe_lt(&point[0], &s->p->p) &&
          sb_fe_lt(&point[1], &s->p->p))) {
        return 0;
    }

    // Verify y^2 = x^3 + ax + b
    sb_fe_mont_square(C_T5(c), &point[1], s->p); // t5 = y^2 * R^-1
    sb_fe_mont_mult(C_Y2(c), C_T5(c), &s->p->r2_mod_p, s->p); // y2 = y^2
    *C_X1(c) = point[0];
    sb_sw_curve_y2(c, s);

    // clang HATES cast to _Bool
    return sb_fe_equal(C_Y1(c), C_Y2(c)) != 0;
}

// A scalar is valid if it is reduced and ∉ {-2, -1, 0, 1} mod N
// Valid scalars are not modified, but invalid scalars may be reduced
static _Bool
sb_sw_scalar_valid(sb_fe_t* const k, const sb_sw_curve_t s[static const 1])
{
    _Bool r = 1;

    r &= sb_fe_lt(k, &s->n->p);
    r &= !sb_fe_equal(k, &SB_FE_ONE); // 1
    r &= !sb_fe_equal(k, &SB_FE_ZERO); // 0

    sb_fe_sub(k, &s->n->p, k); // -k
    r &= !sb_fe_equal(k, &SB_FE_ONE); // -1
    sb_fe_mod_sub(k, k, &SB_FE_ONE, s->n); // (-k) - 1
    r &= !sb_fe_equal(k, &SB_FE_ONE); // -2

    sb_fe_mod_add(k, k, &SB_FE_ONE, s->n); // -k
    sb_fe_sub(k, &s->n->p, k); // k

    return r;
}

#ifdef SB_TEST

static _Bool test_h(const sb_sw_curve_t* s)
{
    sb_sw_context_t m;
    memset(&m, 0, sizeof(m));
    *MULT_Z(&m) = SB_FE_ONE;
    *MULT_K(&m) = (sb_fe_t) SB_FE_CONST(0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                                        0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF);
    sb_fe_sub(MULT_K(&m), MULT_K(&m), &s->n->p);
    sb_fe_sub(MULT_K(&m), MULT_K(&m), &s->n->p);
    const sb_fe_t h_inv = *MULT_K(&m);
    sb_fe_mont_mult(C_T5(&m), MULT_K(&m), &s->n->r2_mod_p,
                    s->n);
    sb_fe_mod_inv_r(C_T5(&m), C_T6(&m), C_T7(&m), s->n);
    sb_fe_mont_mult(MULT_K(&m), C_T5(&m), &SB_FE_ONE, s->n);
    sb_sw_point_mult(&m, s->g_r, s);

    sb_fe_mont_mult(&MULT_POINT(&m)[0], C_X1(&m), &s->p->r2_mod_p, s->p);
    sb_fe_mont_mult(&MULT_POINT(&m)[1], C_Y1(&m), &s->p->r2_mod_p, s->p);

    SB_TEST_ASSERT(sb_fe_equal(&MULT_POINT(&m)[0], &s->h_r[0]));
    SB_TEST_ASSERT(sb_fe_equal(&MULT_POINT(&m)[1], &s->h_r[1]));


    *MULT_K(&m) = h_inv;
    sb_sw_point_mult(&m, MULT_POINT(&m), s);
    sb_fe_mont_mult(C_X2(&m), &s->g_r[0], &SB_FE_ONE, s->p);
    sb_fe_mont_mult(C_Y2(&m), &s->g_r[1], &SB_FE_ONE, s->p);
    SB_TEST_ASSERT(sb_fe_equal(C_X1(&m), C_X2(&m)));
    SB_TEST_ASSERT(sb_fe_equal(C_Y1(&m), C_Y2(&m)));

    return 1;
}

_Bool sb_test_sw_h(void)
{
    SB_TEST_ASSERT(test_h(&SB_CURVE_P256));
    SB_TEST_ASSERT(test_h(&SB_CURVE_SECP256K1));

    return 1;
}

// The following scalars cause exceptions in the ladder and are NOT valid.
_Bool sb_test_exceptions(void)
{
    sb_sw_context_t m;
    memset(&m, 0, sizeof(m));
    *MULT_Z(&m) = SB_FE_ONE;

    // Exceptions produce P, not zero, due to ZVA countermeasures
#define EX_ZERO(c) ((c).p->p)

#define TEST_EX() do { \
    SB_TEST_ASSERT(!sb_sw_scalar_valid(MULT_K(&m), &SB_CURVE_P256)); \
    sb_sw_point_mult(&m, SB_CURVE_P256.g_r, &SB_CURVE_P256); \
    SB_TEST_ASSERT(sb_fe_equal(C_X1(&m), &EX_ZERO(SB_CURVE_P256)) && \
           sb_fe_equal(C_Y1(&m), &EX_ZERO(SB_CURVE_P256))); \
} while (0)

    // k = 1
    *MULT_K(&m) = SB_FE_ONE;
    TEST_EX();

    // k = 0
    *MULT_K(&m) = SB_CURVE_P256.n->p;
    TEST_EX();

    // k = -1
    *MULT_K(&m) = SB_CURVE_P256.n->p;
    sb_fe_sub(MULT_K(&m), MULT_K(&m), &SB_FE_ONE);
    TEST_EX();

    // k = -2
    *MULT_K(&m) = SB_CURVE_P256.n->p;
    sb_fe_sub(MULT_K(&m), MULT_K(&m), &SB_FE_ONE);
    sb_fe_sub(MULT_K(&m), MULT_K(&m), &SB_FE_ONE);
    TEST_EX();
    return 1;
}

#endif

// Places (r, s) into (x2, y2)
static _Bool
sb_sw_sign(sb_sw_context_t g[static const 1],
           const sb_sw_curve_t s[static const 1])
{
    _Bool res = 1;

    sb_sw_point_mult(g, s->g_r, s);


    // This is used to quasi-reduce x1 modulo the curve N:
    *C_X2(g) = *C_X1(g);
    sb_fe_qr(C_X2(g), 0, s->n);

    res &= !sb_fe_equal(C_X2(g), &s->n->p);

    sb_fe_mont_mult(C_T7(g), MULT_K(g), &s->n->r2_mod_p, s->n); // t7 = k * R
    sb_fe_mod_inv_r(C_T7(g), C_T5(g), C_T6(g), s->n); // t7 = k^-1 * R
    sb_fe_mont_mult(C_T6(g), SIGN_PRIVATE(g), &s->n->r2_mod_p,
                    s->n); // t6 = d_A * R
    sb_fe_mont_mult(C_T5(g), C_X2(g), C_T6(g), s->n); // t5 = r * d_A
    sb_fe_mod_add(C_T5(g), C_T5(g), SIGN_MESSAGE(g), s->n); // t5 = z + r * d_A
    sb_fe_mont_mult(C_Y2(g), C_T5(g), C_T7(g),
                    s->n); // y2 = k^-1 * R * (z + r * d_A) * R^-1 mod N

    // mont_mul produces quasi-reduced output
    res &= !sb_fe_equal(C_Y2(g), &s->n->p);

    return res;
}

static _Bool sb_sw_verify(sb_sw_context_t v[static const 1],
                          const sb_sw_curve_t s[static const 1])
{
    _Bool res = 1;

    res &= sb_sw_scalar_valid(VERIFY_QR(v), s);
    res &= sb_sw_scalar_valid(VERIFY_QS(v), s);

    sb_fe_mont_mult(C_T5(v), VERIFY_QS(v), &s->n->r2_mod_p, s->n); // t5 = s * R
    sb_fe_mod_inv_r(C_T5(v), C_T6(v), C_T7(v), s->n); // t5 = s^-1 * R

    sb_fe_mont_mult(MULT_ADD_KG(v), VERIFY_MESSAGE(v), C_T5(v),
                    s->n); // k_G = m * s^-1
    sb_fe_mont_mult(MULT_K(v), VERIFY_QR(v), C_T5(v), s->n); // k_P = r * s^-1

    sb_sw_point_mult_add_z(v, s);

    // This happens when p is some multiple of g that occurs within
    // the ladder, such that additions inadvertently produce a point
    // doubling. When that occurs, the private scalar that generated p is
    // also obvious, so this is bad news. Don't do this.
    res &= !(sb_fe_equal(C_X1(v), &s->p->p) & sb_fe_equal(C_Y1(v), &s->p->p));

    _Bool ver = 0;

    // qr ==? x mod N, but we don't have x, just x * z^2
    // Given that qr is reduced, if it is >= P - N, then it can be used directly
    // if it is < P - N, then we need to try to see if the original value was
    // qr or qr + N
    // Try directly first:
    sb_fe_mont_square(C_T6(v), C_T5(v), s->p); // t6 = Z^2 * R
    sb_fe_mont_mult(C_T7(v), VERIFY_QR(v), C_T6(v), s->p);
    ver |= sb_fe_equal(C_T7(v), C_X1(v));

    // If that didn't work, and qr < P - N, then we need to compare
    // (qr + N) * z^2 against x * z^2

    // Note that this code is probably never used because this situation occurs
    // with very low probability (<2^-128)

    sb_fe_mod_add(C_T5(v), VERIFY_QR(v), &s->n->p, s->p);
    sb_fe_mont_mult(C_T7(v), VERIFY_QR(v), C_T6(v), s->p);
    sb_fe_sub(C_T5(v), &s->p->p, &s->n->p); // t5 = P - N
    ver |= (sb_fe_lt(VERIFY_QR(v), C_T5(v)) &
            sb_fe_equal(C_T7(v), C_X1(v)));

    return res & ver;
}

static sb_error_t sb_sw_curve_from_id(const sb_sw_curve_t** const s,
                                      sb_sw_curve_id_t const curve)
{
    switch (curve) {
#if SB_SW_P256_SUPPORT
        case SB_SW_CURVE_P256: {
            *s = &SB_CURVE_P256;
            return 0;
        }
#endif
#if SB_SW_SECP256K1_SUPPORT
        case SB_SW_CURVE_SECP256K1: {
            *s = &SB_CURVE_SECP256K1;
            return 0;
        }
#endif
#ifdef SB_TEST
        case SB_SW_CURVE_INVALID:
            break;
#endif
    }
    // Huh?
    *s = NULL;
    return SB_ERROR_CURVE_INVALID;
}

// a Z value is invalid if it is zero, since the only point with Z = 0 is the
// point at infinity. Note that this is not expected to ever occur!
static sb_error_t sb_sw_z_valid(const sb_fe_t z[static const 1],
                                const sb_sw_curve_t s[static const 1])
{
    sb_error_t err = SB_SUCCESS;
    err |= SB_ERROR_IF(DRBG_FAILURE, sb_fe_equal(z, &SB_FE_ZERO));
    err |= SB_ERROR_IF(DRBG_FAILURE, sb_fe_equal(z, &s->p->p));
    return err;
}

// Initial Z generation for Z blinding (Coron's third countermeasure)
static sb_error_t sb_sw_generate_z(sb_sw_context_t c[static const 1],
                                   sb_hmac_drbg_state_t* const drbg,
                                   const sb_sw_curve_t s[static const 1],
                                   const sb_byte_t* const d1, const size_t l1,
                                   const sb_byte_t* const d2, const size_t l2,
                                   const sb_byte_t* const d3, const size_t l3)
{
    sb_error_t err = SB_SUCCESS;

    if (drbg) {
        // Use the supplied data as additional input to the DRBG
        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            d1, d2, d3
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            l1, l2, l3
        };

        err |= sb_hmac_drbg_generate_additional_vec(drbg, c->buf, SB_ELEM_BYTES,
                                                    add, add_len);
    } else {
        // Seed the HMAC-DRBG with the input supplied
        err |= sb_hmac_drbg_init(&c->drbg_state,
                                 d1, l1,
                                 d2, l2,
                                 d3, l3);

        // It is a bug if this ever fails; the DRBG limits should allow these
        // inputs.
        SB_ASSERT(!err, "DRBG initialization should never fail.");

        err |= sb_hmac_drbg_generate(&c->drbg_state, c->buf, SB_ELEM_BYTES);
    }

    // It is a bug if this ever fails; the DRBG reseed count should have
    // been checked already, and the DRBG limits should allow these inputs.
    SB_ASSERT(!err, "Z generation should never fail.");

    sb_fe_from_bytes(MULT_Z(c), c->buf, SB_DATA_ENDIAN_BIG);
    err |= sb_sw_z_valid(MULT_Z(c), s);
    return err;
}

//// PUBLIC API:

/// FIPS 186-4-style private key generation. Note that this only tests two
/// candidates; the probability of both candidates failing is extremely low.
sb_error_t sb_sw_generate_private_key(sb_sw_context_t ctx[static const 1],
                                      sb_sw_private_t private[static const 1],
                                      sb_hmac_drbg_state_t drbg[static const 1],
                                      sb_sw_curve_id_t const curve,
                                      sb_data_endian_t const e)
{
    sb_error_t err = SB_SUCCESS;
    memset(ctx, 0, sizeof(sb_sw_context_t));

    const sb_sw_curve_t* s;
    err |= sb_sw_curve_from_id(&s, curve);

    // Avoid modifying the input drbg state if the second generate call fails.
    // It takes two generate calls to generate a private key.
    err |= sb_hmac_drbg_reseed_required(drbg, 2);

    SB_RETURN_ERRORS(err);

    // With P-256, the chance of one random scalar being invalid is <2^-32
    // The chance of two random scalars being invalid is <2^-64
    // With secp256k1, the chance of one random scalar being invalid is <2^-128!
    // Assume that it's OK to fail if both scalars generated are invalid.

    err |= sb_hmac_drbg_generate(drbg, &ctx->buf[0], SB_ELEM_BYTES);
    SB_ASSERT(!err, "Private key generation should never fail.");

    err |= sb_hmac_drbg_generate(drbg, &ctx->buf[SB_ELEM_BYTES], SB_ELEM_BYTES);
    SB_ASSERT(!err, "Private key generation should never fail.");

    sb_fe_from_bytes(MULT_K(ctx), &ctx->buf[0], e);
    sb_fe_from_bytes(MULT_Z(ctx), &ctx->buf[SB_ELEM_BYTES], e);

    // per FIPS 186-4 B.4.2: d = c + 1
    // if this overflows, the value was invalid to begin with
    err |= SB_ERROR_IF(DRBG_FAILURE,
                       sb_fe_add(MULT_K(ctx), MULT_K(ctx), &SB_FE_ONE));
    err |= SB_ERROR_IF(DRBG_FAILURE,
                       sb_fe_add(MULT_Z(ctx), MULT_Z(ctx), &SB_FE_ONE));

    _Bool k1v = sb_sw_scalar_valid(MULT_K(ctx), s);
    sb_fe_ctswap((sb_word_t) (k1v ^ 1), MULT_K(ctx), MULT_Z(ctx));

    err |= SB_ERROR_IF(DRBG_FAILURE, !sb_sw_scalar_valid(MULT_K(ctx), s));

    sb_fe_to_bytes(private->bytes, MULT_K(ctx), e);

    memset(ctx, 0, sizeof(sb_sw_context_t));

    return err;
}

sb_error_t sb_sw_compute_public_key(sb_sw_context_t ctx[static const 1],
                                    sb_sw_public_t public[static const 1],
                                    const sb_sw_private_t private[static const 1],
                                    sb_hmac_drbg_state_t* const drbg,
                                    const sb_sw_curve_id_t curve,
                                    const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;
    memset(ctx, 0, sizeof(sb_sw_context_t));

    const sb_sw_curve_t* s;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    // Return invalid-curve and DRBG errors immediately.
    SB_RETURN_ERRORS(err);

    // Validate the private key before performing any operations.

    sb_fe_from_bytes(MULT_K(ctx), private->bytes, e);
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_valid(MULT_K(ctx), s));

    SB_RETURN_ERRORS(err, ctx);

    // This is cheating: the private key isn't enough entropy to seed a
    // HMAC-DRBG with, so it's used as both entropy and nonce when no DRBG is
    // supplied. When a DRBG is supplied, the private key is used as
    // additional input to the DRBG twice, which shouldn't cause any problems:
    // SP 800-90A rev 1 is fairly clear that additional input can be anything
    // at all, private or public information, as long as it doesn't require
    // protection at a higher security level than the underlying HMAC (which
    // is the same security level as our inputs).

    err |= sb_sw_generate_z(ctx, drbg, s, private->bytes, SB_ELEM_BYTES,
                            private->bytes, SB_ELEM_BYTES, NULL, 0);

    sb_sw_point_mult(ctx, s->g_r, s);

    // The output is quasi-reduced, so the point at infinity is (p, p).
    // This should never occur with valid scalars.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       (sb_fe_equal(C_X1(ctx), &s->p->p) &
                        sb_fe_equal(C_Y1(ctx), &s->p->p)));
    SB_ASSERT(!err, "Montgomery ladder produced the point at infinity from a "
        "valid scalar.");

    sb_fe_to_bytes(public->bytes, C_X1(ctx), e);
    sb_fe_to_bytes(public->bytes + SB_ELEM_BYTES, C_Y1(ctx), e);

    memset(ctx, 0, sizeof(sb_sw_context_t));

    return err;
}

sb_error_t sb_sw_valid_public_key(sb_sw_context_t ctx[static const 1],
                                  const sb_sw_public_t public[static const 1],
                                  const sb_sw_curve_id_t curve,
                                  const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;

    memset(ctx, 0, sizeof(sb_sw_context_t));

    const sb_sw_curve_t* s;
    err |= sb_sw_curve_from_id(&s, curve);

    SB_RETURN_ERRORS(err);

    sb_fe_from_bytes(&MULT_POINT(ctx)[0], public->bytes, e);
    sb_fe_from_bytes(&MULT_POINT(ctx)[1], public->bytes + SB_ELEM_BYTES, e);

    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID,
                       !sb_sw_point_valid(MULT_POINT(ctx), ctx, s));

    memset(ctx, 0, sizeof(sb_sw_context_t));

    return err;
}

sb_error_t sb_sw_shared_secret(sb_sw_context_t ctx[static const 1],
                               sb_sw_shared_secret_t secret[static const 1],
                               const sb_sw_private_t private[static const 1],
                               const sb_sw_public_t public[static const 1],
                               sb_hmac_drbg_state_t* const drbg,
                               const sb_sw_curve_id_t curve,
                               const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;
    memset(ctx, 0, sizeof(sb_sw_context_t));

    const sb_sw_curve_t* s;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    SB_RETURN_ERRORS(err);

    // Only the X coordinate of the public key is used as the nonce, since
    // the Y coordinate is not an independent input.
    err |= sb_sw_generate_z(ctx, drbg, s, private->bytes, SB_ELEM_BYTES,
                            public->bytes, SB_ELEM_BYTES,
                            NULL, 0);

    sb_fe_from_bytes(MULT_K(ctx), private->bytes, e);

    sb_fe_from_bytes(&MULT_POINT(ctx)[0], public->bytes, e);
    sb_fe_from_bytes(&MULT_POINT(ctx)[1], public->bytes + SB_ELEM_BYTES, e);

    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_valid(MULT_K(ctx), s));
    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID,
                       !sb_sw_point_valid(MULT_POINT(ctx), ctx, s));

    // Return errors here to prevent not-on-curve public keys from being used
    // in a power side-channel attack.
    SB_RETURN_ERRORS(err, ctx);

    // Pre-multiply the point's x and y by R
    sb_fe_mont_mult(C_X1(ctx), &MULT_POINT(ctx)[0], &s->p->r2_mod_p, s->p);
    sb_fe_mont_mult(C_Y1(ctx), &MULT_POINT(ctx)[1], &s->p->r2_mod_p, s->p);
    MULT_POINT(ctx)[0] = *C_X1(ctx);
    MULT_POINT(ctx)[1] = *C_Y1(ctx);

    sb_sw_point_mult(ctx, MULT_POINT(ctx), s);

    // This should never occur with a valid private scalar.
    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       (sb_fe_equal(C_X1(ctx), &s->p->p) &
                        sb_fe_equal(C_Y1(ctx), &s->p->p)));
    SB_ASSERT(!err, "Montgomery ladder produced the point at infinity from a "
        "valid scalar.");

    sb_fe_to_bytes(secret->bytes, C_X1(ctx), e);

    memset(ctx, 0, sizeof(sb_sw_context_t));

    return err;
}

#ifdef SB_TEST

// This is an EXTREMELY dangerous method and is not exposed in the public
// header. Do not under any circumstances call this function unless you are
// running NIST CAVP tests.

// Prototype to satisfy the compiler...

sb_error_t sb_sw_sign_message_digest_with_k_beware_of_the_leopard
    (sb_sw_context_t ctx[static 1],
     sb_sw_signature_t signature[static 1],
     const sb_sw_private_t private[static 1],
     const sb_sw_message_digest_t message[static 1],
     const sb_sw_private_t* k,
     sb_hmac_drbg_state_t* drbg,
     sb_sw_curve_id_t curve,
     sb_data_endian_t e);

#endif

sb_error_t sb_sw_sign_message_digest(sb_sw_context_t ctx[static const 1],
                                     sb_sw_signature_t signature[static const 1],
                                     const sb_sw_private_t private[static const 1],
                                     const sb_sw_message_digest_t message[static const 1],
                                     sb_hmac_drbg_state_t* const drbg,
                                     const sb_sw_curve_id_t curve,
                                     const sb_data_endian_t e)
#ifdef SB_TEST
{
    return sb_sw_sign_message_digest_with_k_beware_of_the_leopard
        (ctx, signature, private, message, NULL, drbg, curve, e);
}

sb_error_t sb_sw_sign_message_digest_with_k_beware_of_the_leopard
    (sb_sw_context_t ctx[static const 1],
     sb_sw_signature_t signature[static const 1],
     const sb_sw_private_t private[static const 1],
     const sb_sw_message_digest_t message[static const 1],
     const sb_sw_private_t* const k,
     sb_hmac_drbg_state_t* const drbg,
     const sb_sw_curve_id_t curve,
     const sb_data_endian_t e)
#endif
{
    sb_error_t err = SB_SUCCESS;
    memset(ctx, 0, sizeof(sb_sw_context_t));

    const sb_sw_curve_t* s;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    // It takes two calls to generate a per-message secret and one to
    // generate an initial Z
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 3);
    }

    SB_RETURN_ERRORS(err);

    sb_fe_from_bytes(SIGN_PRIVATE(ctx), private->bytes, e);
    sb_fe_from_bytes(SIGN_MESSAGE(ctx), message->bytes, e);

    err |= SB_ERROR_IF(PRIVATE_KEY_INVALID,
                       !sb_sw_scalar_valid(SIGN_PRIVATE(ctx), s));

    // Reduce the message modulo N
    sb_fe_mod_sub(SIGN_MESSAGE(ctx), SIGN_MESSAGE(ctx), &s->n->p, s->n);

#ifdef SB_TEST
    // Inject the provided per-message secret
    if (k) {
        memcpy(ctx->buf, k, SB_ELEM_BYTES);
    } else
#endif
    if (drbg) {
        // FIPS 186-4-style per-message secret generation
        // The private key and message are used (in native endianness) as
        // additional input to the DRBG in order to prevent catastrophic
        // entropy failure.

        const sb_byte_t* const add[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            private->bytes, message->bytes
        };

        const size_t add_len[SB_HMAC_DRBG_ADD_VECTOR_LEN] = {
            SB_ELEM_BYTES, SB_ELEM_BYTES
        };

        err |= sb_hmac_drbg_generate_additional_vec(drbg, &ctx->buf[0],
                                                    SB_ELEM_BYTES, add,
                                                    add_len);

        err |= sb_hmac_drbg_generate(&ctx->drbg_state, &ctx->buf[SB_ELEM_BYTES],
                                     SB_ELEM_BYTES);

    } else {
        // RFC6979 deterministic signature generation

        // Convert the private scalar and reduced message back into a
        // big-endian byte string
        sb_fe_to_bytes(&ctx->buf[0], SIGN_PRIVATE(ctx),
                       SB_DATA_ENDIAN_BIG);
        sb_fe_to_bytes(&ctx->buf[SB_ELEM_BYTES], SIGN_MESSAGE(ctx),
                       SB_DATA_ENDIAN_BIG);

        err |=
            sb_hmac_drbg_init(&ctx->drbg_state, &ctx->buf[0], SB_ELEM_BYTES,
                              &ctx->buf[SB_ELEM_BYTES], SB_ELEM_BYTES, NULL, 0);
        SB_ASSERT(!err, "DRBG initialization should never fail.");

        err |= sb_hmac_drbg_generate(&ctx->drbg_state, &ctx->buf[0],
                                     SB_ELEM_BYTES);

        err |= sb_hmac_drbg_generate(&ctx->drbg_state, &ctx->buf[SB_ELEM_BYTES],
                                     SB_ELEM_BYTES);
    }

    SB_ASSERT(!err, "The DRBG should never fail to generate a "
        "per-message secret.");

    sb_fe_from_bytes(MULT_K(ctx), &ctx->buf[0], SB_DATA_ENDIAN_BIG);
    sb_fe_from_bytes(MULT_Z(ctx), &ctx->buf[SB_ELEM_BYTES], SB_DATA_ENDIAN_BIG);

    if (drbg) {
        // per FIPS 186-4 B.5.2: k = c + 1
        // if this overflows, the value was invalid to begin with
        err |= SB_ERROR_IF(DRBG_FAILURE,
                           sb_fe_add(MULT_K(ctx), MULT_K(ctx), &SB_FE_ONE));
        err |= SB_ERROR_IF(DRBG_FAILURE,
                           sb_fe_add(MULT_Z(ctx), MULT_Z(ctx), &SB_FE_ONE));
    }

    // Note that this step rejects the scalars -2, -1, and 1, which both FIPS
    // 186-4 and RFC6979 would accept. The probability of this happening in
    // practice is too remote to consider, so the deviation from standard is
    // acceptable.

    _Bool k1v = sb_sw_scalar_valid(MULT_K(ctx), s);
    sb_fe_ctswap((sb_word_t) (k1v ^ 1), MULT_K(ctx), MULT_Z(ctx));

    err |= SB_ERROR_IF(DRBG_FAILURE, !sb_sw_scalar_valid(MULT_K(ctx), s));

    // And now generate an initial Z
    err |= sb_hmac_drbg_generate((drbg ? drbg : &ctx->drbg_state),
                                 &ctx->buf[0], SB_ELEM_BYTES);
    SB_ASSERT(!err, "The DRBG should never fail to generate a Z value.");

    sb_fe_from_bytes(MULT_Z(ctx), &ctx->buf[0], SB_DATA_ENDIAN_BIG);
    err |= sb_sw_z_valid(MULT_Z(ctx), s);

    // If sb_sw_sign fails, the DRBG produced an extremely low-probability k
    err |= SB_ERROR_IF(DRBG_FAILURE, !sb_sw_sign(ctx, s));

    sb_fe_to_bytes(signature->bytes, C_X2(ctx), e);
    sb_fe_to_bytes(signature->bytes + SB_ELEM_BYTES, C_Y2(ctx), e);

    memset(ctx, 0, sizeof(sb_sw_context_t));
    return err;
}

sb_error_t sb_sw_verify_signature(sb_sw_context_t ctx[static const 1],
                                  const sb_sw_signature_t signature[static const 1],
                                  const sb_sw_public_t public[static const 1],
                                  const sb_sw_message_digest_t message[static const 1],
                                  sb_hmac_drbg_state_t* const drbg,
                                  const sb_sw_curve_id_t curve,
                                  const sb_data_endian_t e)
{
    sb_error_t err = SB_SUCCESS;
    memset(ctx, 0, sizeof(sb_sw_context_t));

    const sb_sw_curve_t* s;
    err |= sb_sw_curve_from_id(&s, curve);

    // Bail out early if the DRBG needs to be reseeded
    if (drbg != NULL) {
        err |= sb_hmac_drbg_reseed_required(drbg, 1);
    }

    SB_RETURN_ERRORS(err);

    // Only the X coordinate of the public key is used as input, since
    // the Y coordinate is not an independent input. When no DRBG is
    // supplied, the message is used as personalization string, but the
    // division here is somewhat arbitrary since it's just concatenated as
    // HMAC input with the entropy and nonce. When a DRBG is supplied, the
    // public key, signature, and message are all used as additional input.
    err |= sb_sw_generate_z(ctx, drbg, s, public->bytes, SB_ELEM_BYTES,
                            signature->bytes, 2 * SB_ELEM_BYTES,
                            message->bytes, SB_ELEM_BYTES);

    sb_fe_from_bytes(VERIFY_QR(ctx), signature->bytes, e);
    sb_fe_from_bytes(VERIFY_QS(ctx), signature->bytes + SB_ELEM_BYTES, e);
    sb_fe_from_bytes(VERIFY_MESSAGE(ctx), message->bytes, e);

    sb_fe_from_bytes(&MULT_POINT(ctx)[0], public->bytes, e);
    sb_fe_from_bytes(&MULT_POINT(ctx)[1], public->bytes + SB_ELEM_BYTES, e);
    err |= SB_ERROR_IF(PUBLIC_KEY_INVALID,
                       !sb_sw_point_valid(MULT_POINT(ctx), ctx, s));

    // Return early if the public key is invalid. If an attacker can modify
    // the public key so that it is invalid, they can presumably also replace
    // the public key with a different, valid key. In the event that the
    // public key is incorrect or corrupt, better to avoid computing anything
    // on the signature at all.

    SB_RETURN_ERRORS(err, ctx);

    err |= SB_ERROR_IF(SIGNATURE_INVALID, !sb_sw_verify(ctx, s));

    memset(ctx, 0, sizeof(sb_sw_context_t));
    return err;
}

//// End of public API; tests follow.

#ifdef SB_TEST

static const sb_sw_private_t TEST_PRIV_1 = {
    {
        0x5E, 0x7F, 0x68, 0x59, 0x05, 0xE6, 0xB8, 0x08,
        0xAE, 0xF8, 0xE9, 0x2D, 0x59, 0x6F, 0xAC, 0x9B,
        0xC5, 0x33, 0x6C, 0x2B, 0xB8, 0x11, 0x3C, 0x87,
        0x7E, 0x7E, 0x5B, 0xBD, 0xB1, 0x4E, 0x83, 0x74
    }};

// is NOT the public key for TEST_PRIV_1
static const sb_sw_public_t TEST_PUB_1 = {
    {
        0xA7, 0xE2, 0x9A, 0x43, 0x86, 0x95, 0xCF, 0xD0,
        0x0A, 0x0A, 0xCB, 0x0D, 0x86, 0x1C, 0x6C, 0xA5,
        0x99, 0xF8, 0xB5, 0xC4, 0x93, 0xC9, 0xA2, 0x78,
        0xBA, 0x85, 0xDD, 0x46, 0x45, 0x03, 0xD7, 0x2D,
        0x0D, 0x76, 0xCE, 0xD9, 0xFE, 0x9F, 0x7F, 0x92,
        0x05, 0x05, 0x84, 0xEC, 0x58, 0x0D, 0x57, 0x51,
        0x29, 0xA9, 0xB4, 0x21, 0x54, 0x15, 0x0A, 0x04,
        0x45, 0x89, 0xBE, 0x2A, 0x25, 0xC2, 0xB0, 0x6D
    }
};

_Bool sb_test_shared_secret(void)
{
    static const sb_sw_private_t secret = {
        {
            0xB5, 0xF9, 0x02, 0x52, 0xB8, 0xCA, 0xF8, 0x46,
            0x3B, 0x8B, 0x73, 0x77, 0x48, 0x32, 0x3B, 0x89,
            0xD2, 0x54, 0x35, 0x88, 0xE1, 0x29, 0xDF, 0x6E,
            0x33, 0xE1, 0x68, 0xEC, 0x31, 0x72, 0x19, 0x22
        }
    };

    sb_sw_shared_secret_t out;
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_shared_secret(&ct, &out, &TEST_PRIV_1, &TEST_PUB_1, NULL,
                            SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(out, secret);
    return 1;
}

_Bool sb_test_shared_secret_cavp_1(void)
{
    static const sb_sw_public_t pub1 = {
        {
            0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c,
            0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9,
            0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4,
            0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
            0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06,
            0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5,
            0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0,
            0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac
        }
    };

    static const sb_sw_private_t priv2 = {
        {
            0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda,
            0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0,
            0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e,
            0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34
        }
    };

    static const sb_sw_public_t pub2 = {
        {
            0xea, 0xd2, 0x18, 0x59, 0x01, 0x19, 0xe8, 0x87,
            0x6b, 0x29, 0x14, 0x6f, 0xf8, 0x9c, 0xa6, 0x17,
            0x70, 0xc4, 0xed, 0xbb, 0xf9, 0x7d, 0x38, 0xce,
            0x38, 0x5e, 0xd2, 0x81, 0xd8, 0xa6, 0xb2, 0x30,
            0x28, 0xaf, 0x61, 0x28, 0x1f, 0xd3, 0x5e, 0x2f,
            0xa7, 0x00, 0x25, 0x23, 0xac, 0xc8, 0x5a, 0x42,
            0x9c, 0xb0, 0x6e, 0xe6, 0x64, 0x83, 0x25, 0x38,
            0x9f, 0x59, 0xed, 0xfc, 0xe1, 0x40, 0x51, 0x41
        }
    };

    static const sb_sw_shared_secret_t secret = {
        {
            0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01,
            0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25,
            0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68,
            0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b
        }
    };

    sb_sw_context_t ct;
    sb_sw_shared_secret_t out;
    sb_sw_public_t c_pub2;
    SB_TEST_ASSERT_SUCCESS(sb_sw_compute_public_key(&ct, &c_pub2, &priv2, NULL,
                                                    SB_SW_CURVE_P256,
                                                    SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(c_pub2, pub2);
    SB_TEST_ASSERT_SUCCESS(sb_sw_shared_secret(&ct, &out, &priv2, &pub1, NULL,
                                               SB_SW_CURVE_P256,
                                               SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(out, secret);
    return 1;
}

static const sb_sw_private_t TEST_PRIV_2 = {
    {
        0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16,
        0x6B, 0x5C, 0x21, 0x57, 0x67, 0xB1, 0xD6, 0x93,
        0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12,
        0x7B, 0x8A, 0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21
    }
};

static const sb_sw_public_t TEST_PUB_2 = {
    {
        0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31,
        0xC9, 0x61, 0xEB, 0x74, 0xC6, 0x35, 0x6D, 0x68,
        0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
        0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
        0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99,
        0xA4, 0x1A, 0xE9, 0xE9, 0x56, 0x28, 0xBC, 0x64,
        0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
        0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99
    }
};

_Bool sb_test_compute_public(void)
{
    sb_sw_public_t pub;
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_compute_public_key(&ct, &pub, &TEST_PRIV_2, NULL,
                                 SB_SW_CURVE_P256,
                                 SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(pub, TEST_PUB_2);
    return 1;
}

_Bool sb_test_valid_public(void)
{
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_valid_public_key(&ct, &TEST_PUB_1, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_valid_public_key(&ct, &TEST_PUB_2, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_ERROR(
        sb_sw_valid_public_key(&ct, &TEST_PUB_2, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_LITTLE),
        SB_ERROR_PUBLIC_KEY_INVALID);
    return 1;
}

static const sb_sw_message_digest_t TEST_MESSAGE = {
    {
        0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1,
        0xE2, 0xAD, 0xE1, 0xD6, 0x94, 0xF4, 0x1F, 0xC7,
        0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
        0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF
    }
};

static const sb_sw_signature_t TEST_SIG = {
    {
        0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD,
        0x11, 0x40, 0xDD, 0x9C, 0xD4, 0x5E, 0x81, 0xD6,
        0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
        0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
        0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41,
        0xD4, 0x36, 0xC7, 0xA1, 0xB6, 0xE2, 0x9F, 0x65,
        0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
        0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8
    }
};

_Bool sb_test_sign_rfc6979(void)
{
    sb_sw_context_t ct;
    sb_sw_signature_t out;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_digest(&ct, &out, &TEST_PRIV_2, &TEST_MESSAGE,
                                  NULL, SB_SW_CURVE_P256,
                                  SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(TEST_SIG, out);
    return 1;
}

_Bool sb_test_verify(void)
{
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_verify_signature(&ct, &TEST_SIG, &TEST_PUB_2, &TEST_MESSAGE,
                               NULL, SB_SW_CURVE_P256,
                               SB_DATA_ENDIAN_BIG));
    return 1;
}

_Bool sb_test_verify_invalid(void)
{
    sb_sw_context_t ct;
    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &TEST_SIG, &TEST_PUB_1, &TEST_MESSAGE,
                               NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_SIGNATURE_INVALID);

    // This tests that verifying a signature with an invalid public key will
    // fail with the correct indication:
    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &TEST_SIG, &TEST_SIG, &TEST_MESSAGE,
                               NULL, SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PUBLIC_KEY_INVALID);
    return 1;
}

// This test verifies that signing different messages with the same DRBG
// state will not result in catastrophic per-signature secret reuse
_Bool sb_test_sign_catastrophe(void)
{
    sb_sw_context_t ct;
    sb_sw_signature_t s, s2, s3;
    sb_sw_message_digest_t m = TEST_MESSAGE;
    sb_hmac_drbg_state_t drbg;
    static const sb_byte_t NULL_ENTROPY[32] = { 0 };

    // Initialize drbg to predictable state
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_init(&drbg, NULL_ENTROPY, 32, NULL_ENTROPY, 32, NULL,
                          0));

    // Sign message
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_digest(&ct, &s, &TEST_PRIV_1, &m, &drbg,
                                  SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));

    // Reinitialize drbg state
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_init(&drbg, NULL_ENTROPY, 32, NULL_ENTROPY, 32, NULL,
                          0));

    // Sign the same message, which should produce the same signature
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_digest(&ct, &s2, &TEST_PRIV_1, &m, &drbg,
                                  SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(s, s2);

    // Reinitialize drbg state
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_init(&drbg, NULL_ENTROPY, 32, NULL_ENTROPY, 32, NULL,
                          0));
    // Sign a different message, which should produce a different R because a
    // different k was used!
    m.bytes[0] ^= 1;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_sign_message_digest(&ct, &s3, &TEST_PRIV_1, &m, &drbg,
                                  SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_NOT_EQUAL(s, s3, 32);

    // For manual verification: if you break sb_sw_sign_message_digest by
    // only providing the private key as additional data to the first
    // generate call, this test will fail!
    return 1;
}

// Between the sign_iter and shared_iter tests, every function that takes an
// optional drbg input is called with a drbg.
static _Bool sb_test_sign_iter_c(const sb_sw_curve_id_t c)
{
    sb_sw_private_t d;
    sb_sw_public_t p;
    sb_sw_signature_t s;
    sb_sw_context_t ct;
    size_t i = 0;

    sb_hmac_drbg_state_t drbg;
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_init(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                          TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2), NULL, 0)
    );
    do {
        SB_TEST_ASSERT_SUCCESS(sb_sw_generate_private_key(&ct, &d, &drbg, c,
                                                          SB_DATA_ENDIAN_BIG));
        SB_TEST_ASSERT_SUCCESS(sb_sw_compute_public_key(&ct, &p, &d, &drbg, c,
                                                        SB_DATA_ENDIAN_BIG));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_sign_message_digest(&ct, &s, &d, &TEST_MESSAGE, &drbg,
                                      c, SB_DATA_ENDIAN_BIG));
        SB_TEST_ASSERT_SUCCESS(
            sb_sw_verify_signature(&ct, &s, &p, &TEST_MESSAGE, &drbg, c,
                                   SB_DATA_ENDIAN_BIG));
        SB_TEST_ASSERT_SUCCESS(
            sb_hmac_drbg_reseed(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                                TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2))
        );
        i++;
    } while (i < 128);
    return 1;
}

_Bool sb_test_sign_iter(void)
{
    return sb_test_sign_iter_c(SB_SW_CURVE_P256);
}

_Bool sb_test_sign_iter_k256(void)
{
    return sb_test_sign_iter_c(SB_SW_CURVE_SECP256K1);
}

static _Bool sb_test_shared_iter_c(const sb_sw_curve_id_t c)
{
    sb_sw_private_t d, d2;
    sb_sw_public_t p, p2;
    sb_sw_shared_secret_t s, s2;
    sb_sw_context_t ct;
    size_t i = 0;

    sb_hmac_drbg_state_t drbg;
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_init(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                          TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2), NULL, 0)
    );
    do {
        SB_TEST_ASSERT_SUCCESS(sb_sw_generate_private_key(&ct, &d, &drbg, c,
                                                          SB_DATA_ENDIAN_LITTLE));
        SB_TEST_ASSERT_SUCCESS(sb_sw_compute_public_key(&ct, &p, &d, &drbg, c,
                                                        SB_DATA_ENDIAN_LITTLE));
        SB_TEST_ASSERT_SUCCESS(sb_sw_generate_private_key(&ct, &d2, &drbg, c,
                                                          SB_DATA_ENDIAN_LITTLE));
        SB_TEST_ASSERT_SUCCESS(sb_sw_compute_public_key(&ct, &p2, &d2, &drbg, c,
                                                        SB_DATA_ENDIAN_LITTLE));
        SB_TEST_ASSERT_SUCCESS(sb_sw_shared_secret(&ct, &s, &d, &p2, &drbg, c,
                                                   SB_DATA_ENDIAN_LITTLE));
        SB_TEST_ASSERT_SUCCESS(sb_sw_shared_secret(&ct, &s2, &d2, &p, &drbg, c,
                                                   SB_DATA_ENDIAN_LITTLE));
        SB_TEST_ASSERT_EQUAL(s, s2);

        SB_TEST_ASSERT_SUCCESS(
            sb_hmac_drbg_reseed(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                                TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2))
        );
        i++;
    } while (i < 128);
    return 1;
}

_Bool sb_test_shared_iter(void)
{
    return sb_test_shared_iter_c(SB_SW_CURVE_P256);
}

_Bool sb_test_shared_iter_k256(void)
{
    return sb_test_shared_iter_c(SB_SW_CURVE_SECP256K1);
}

// This test shamelessly borrowed from libsecp256k1
_Bool sb_test_shared_secret_k256(void)
{
    static const sb_sw_private_t d = {
        {
            0x64, 0x9D, 0x4F, 0x77, 0xC4, 0x24, 0x2D, 0xF7,
            0x7F, 0x20, 0x79, 0xC9, 0x14, 0x53, 0x03, 0x27,
            0xA3, 0x1B, 0x87, 0x6A, 0xD2, 0xD8, 0xCE, 0x2A,
            0x22, 0x36, 0xD5, 0xC6, 0xD7, 0xB2, 0x02, 0x9B
        }};
    static const sb_sw_public_t p = {
        {
            0x6D, 0x98, 0x65, 0x44, 0x57, 0xFF, 0x52, 0xB8,
            0xCF, 0x1B, 0x81, 0x26, 0x5B, 0x80, 0x2A, 0x5B,
            0xA9, 0x7F, 0x92, 0x63, 0xB1, 0xE8, 0x80, 0x44,
            0x93, 0x35, 0x13, 0x25, 0x91, 0xBC, 0x45, 0x0A,
            0x53, 0x5C, 0x59, 0xF7, 0x32, 0x5E, 0x5D, 0x2B,
            0xC3, 0x91, 0xFB, 0xE8, 0x3C, 0x12, 0x78, 0x7C,
            0x33, 0x7E, 0x4A, 0x98, 0xE8, 0x2A, 0x90, 0x11,
            0x01, 0x23, 0xBA, 0x37, 0xDD, 0x76, 0x9C, 0x7D
        }};
    static const sb_sw_shared_secret_t s = {
        {
            0x23, 0x77, 0x36, 0x84, 0x4D, 0x20, 0x9D, 0xC7,
            0x09, 0x8A, 0x78, 0x6F, 0x20, 0xD0, 0x6F, 0xCD,
            0x07, 0x0A, 0x38, 0xBF, 0xC1, 0x1A, 0xC6, 0x51,
            0x03, 0x00, 0x43, 0x19, 0x1E, 0x2A, 0x87, 0x86
        }};
    sb_sw_shared_secret_t out;
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_shared_secret(&ct, &out, &d, &p, NULL, SB_SW_CURVE_SECP256K1,
                            SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(s, out);
    return 1;
}

_Bool sb_test_sign_k256(void)
{
    static const sb_sw_message_digest_t m = {
        {
            0x4B, 0x68, 0x8D, 0xF4, 0x0B, 0xCE, 0xDB, 0xE6,
            0x41, 0xDD, 0xB1, 0x6F, 0xF0, 0xA1, 0x84, 0x2D,
            0x9C, 0x67, 0xEA, 0x1C, 0x3B, 0xF6, 0x3F, 0x3E,
            0x04, 0x71, 0xBA, 0xA6, 0x64, 0x53, 0x1D, 0x1A
        }};
    static const sb_sw_private_t d = {
        {
            0xEB, 0xB2, 0xC0, 0x82, 0xFD, 0x77, 0x27, 0x89,
            0x0A, 0x28, 0xAC, 0x82, 0xF6, 0xBD, 0xF9, 0x7B,
            0xAD, 0x8D, 0xE9, 0xF5, 0xD7, 0xC9, 0x02, 0x86,
            0x92, 0xDE, 0x1A, 0x25, 0x5C, 0xAD, 0x3E, 0x0F
        }};
    static const sb_sw_public_t p = {
        {
            0x77, 0x9D, 0xD1, 0x97, 0xA5, 0xDF, 0x97, 0x7E,
            0xD2, 0xCF, 0x6C, 0xB3, 0x1D, 0x82, 0xD4, 0x33,
            0x28, 0xB7, 0x90, 0xDC, 0x6B, 0x3B, 0x7D, 0x44,
            0x37, 0xA4, 0x27, 0xBD, 0x58, 0x47, 0xDF, 0xCD,
            0xE9, 0x4B, 0x72, 0x4A, 0x55, 0x5B, 0x6D, 0x01,
            0x7B, 0xB7, 0x60, 0x7C, 0x3E, 0x32, 0x81, 0xDA,
            0xF5, 0xB1, 0x69, 0x9D, 0x6E, 0xF4, 0x12, 0x49,
            0x75, 0xC9, 0x23, 0x7B, 0x91, 0x7D, 0x42, 0x6F
        }};

    sb_sw_signature_t out;
    sb_sw_public_t pub_out;
    sb_sw_context_t ct;
    SB_TEST_ASSERT_SUCCESS(
        sb_sw_valid_public_key(&ct, &p, SB_SW_CURVE_SECP256K1,
                               SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(sb_sw_compute_public_key(&ct, &pub_out, &d, NULL,
                                                    SB_SW_CURVE_SECP256K1,
                                                    SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_EQUAL(pub_out, p);
    SB_TEST_ASSERT_SUCCESS(sb_sw_sign_message_digest(&ct, &out, &d, &m, NULL,
                                                     SB_SW_CURVE_SECP256K1,
                                                     SB_DATA_ENDIAN_BIG));
    SB_TEST_ASSERT_SUCCESS(sb_sw_verify_signature(&ct, &out, &p, &m, NULL,
                                                  SB_SW_CURVE_SECP256K1,
                                                  SB_DATA_ENDIAN_BIG));
    return 1;
}

_Bool sb_test_sw_early_errors(void)
{
    sb_hmac_drbg_state_t drbg;
    SB_TEST_ASSERT_SUCCESS(
        sb_hmac_drbg_init(&drbg, TEST_PRIV_1.bytes, sizeof(TEST_PRIV_1),
                          TEST_PRIV_2.bytes, sizeof(TEST_PRIV_2), NULL, 0)
    );
    drbg.reseed_counter = SB_HMAC_DRBG_RESEED_INTERVAL + 1;

    // Test that calling functions with an invalid curve and a DRBG that must
    // be reseeded fails with the correct error indications:
    sb_sw_context_t ct;
    sb_single_t s;
    sb_double_t d;
    SB_TEST_ASSERT_ERROR(sb_sw_generate_private_key(&ct, &s, &drbg,
                                                    SB_SW_CURVE_INVALID,
                                                    SB_DATA_ENDIAN_BIG),
                         (SB_ERROR_CURVE_INVALID | SB_ERROR_RESEED_REQUIRED));
    SB_TEST_ASSERT_ERROR(sb_sw_compute_public_key(&ct, &d, &TEST_PRIV_1, &drbg,
                                                  SB_SW_CURVE_INVALID,
                                                  SB_DATA_ENDIAN_BIG),
                         (SB_ERROR_CURVE_INVALID | SB_ERROR_RESEED_REQUIRED));
    SB_TEST_ASSERT_ERROR(sb_sw_valid_public_key(&ct, &d,
                                                SB_SW_CURVE_INVALID,
                                                SB_DATA_ENDIAN_BIG),
                         SB_ERROR_CURVE_INVALID);
    SB_TEST_ASSERT_ERROR(
        sb_sw_shared_secret(&ct, &s, &TEST_PRIV_1, &TEST_PUB_1, &drbg,
                            SB_SW_CURVE_INVALID, SB_DATA_ENDIAN_BIG),
        (SB_ERROR_CURVE_INVALID | SB_ERROR_RESEED_REQUIRED));
    SB_TEST_ASSERT_ERROR(
        sb_sw_sign_message_digest(&ct, &d, &TEST_PRIV_1, &TEST_MESSAGE,
                                  &drbg, SB_SW_CURVE_INVALID,
                                  SB_DATA_ENDIAN_BIG),
        (SB_ERROR_CURVE_INVALID | SB_ERROR_RESEED_REQUIRED));
    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &TEST_SIG, &TEST_PUB_1, &TEST_MESSAGE,
                               &drbg, SB_SW_CURVE_INVALID,
                               SB_DATA_ENDIAN_BIG),
        (SB_ERROR_CURVE_INVALID | SB_ERROR_RESEED_REQUIRED));

    d = TEST_PUB_1;
    d.bytes[0] ^= 1;

    // Test that calling functions which accept a curve point fail with the
    // correct error indications when the point is not on the curve:

    SB_TEST_ASSERT_ERROR(
        sb_sw_shared_secret(&ct, &s, &TEST_PRIV_1, &d, NULL,
                            SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PUBLIC_KEY_INVALID);

    SB_TEST_ASSERT_ERROR(
        sb_sw_verify_signature(&ct, &TEST_SIG, &d, &TEST_MESSAGE, NULL,
                               SB_SW_CURVE_P256, SB_DATA_ENDIAN_BIG),
        SB_ERROR_PUBLIC_KEY_INVALID);

    return 1;
}

#endif
