/*
 * sb_fe.h: private API for constant time prime-field element operations
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

#ifndef SB_FE_H
#define SB_FE_H

#include <stdint.h>
#include <stddef.h>
#include "sb_types.h"

typedef size_t sb_wordcount_t;
typedef size_t sb_bitcount_t;

#define SB_FE_BITS  256

#if !defined(SB_MUL_SIZE)
#define SB_MUL_SIZE 4
#endif

#if SB_MUL_SIZE == 8

typedef uint64_t sb_word_t;
typedef __uint128_t sb_dword_t;

#define SB_FE_WORDS 4

static const sb_bitcount_t SB_WORD_BITS = 64;
static const sb_word_t SB_WORD_BITS_SHIFT = 6;
static const sb_word_t SB_WORD_BITS_MASK = 0x3F;

#define SB_WORD_EXPAND(d) d

#elif SB_MUL_SIZE == 4

typedef uint32_t sb_word_t;
typedef uint64_t sb_dword_t;

#define SB_FE_WORDS 8

static const sb_bitcount_t SB_WORD_BITS = 32;
static const sb_word_t SB_WORD_BITS_SHIFT = 5;
static const sb_word_t SB_WORD_BITS_MASK = 0x1F;

#define SB_WORD_EXPAND(d) (sb_word_t) (d), (sb_word_t) ((d) >> UINT64_C(32))

#elif SB_MUL_SIZE == 2

typedef uint16_t sb_word_t;
typedef uint32_t sb_dword_t;

#define SB_FE_WORDS 16

static const sb_bitcount_t SB_WORD_BITS = 16;
static const sb_word_t SB_WORD_BITS_SHIFT = 4;
static const sb_word_t SB_WORD_BITS_MASK = 0x0F;

#define SB_WORD_EXPAND(d) (sb_word_t) ((d) >> UINT64_C(0)), \
                          (sb_word_t) ((d) >> UINT64_C(16)), \
                          (sb_word_t) ((d) >> UINT64_C(32)), \
                          (sb_word_t) ((d) >> UINT64_C(48))

#elif SB_MUL_SIZE == 1

typedef uint8_t sb_word_t;
typedef uint16_t sb_dword_t;

#define SB_FE_WORDS 32

static const sb_bitcount_t SB_WORD_BITS = 8;
static const sb_word_t SB_WORD_BITS_SHIFT = 3;
static const sb_word_t SB_WORD_BITS_MASK = 0x07;

#define SB_WORD_EXPAND(d) (sb_word_t) ((d) >> UINT64_C(0)), \
                          (sb_word_t) ((d) >> UINT64_C(8)), \
                          (sb_word_t) ((d) >> UINT64_C(16)), \
                          (sb_word_t) ((d) >> UINT64_C(24)), \
                          (sb_word_t) ((d) >> UINT64_C(32)), \
                          (sb_word_t) ((d) >> UINT64_C(40)), \
                          (sb_word_t) ((d) >> UINT64_C(48)), \
                          (sb_word_t) ((d) >> UINT64_C(56))

#else

#error "SB_MUL_SIZE is invalid"

#endif

// Always unroll the inner multiplication loop by default
#if !defined(SB_UNROLL)
#define SB_UNROLL 1
#endif

// Note: when porting to a new compiler, check to see if it's smart enough to
// optimize out the dead code when v >= SB_FE_WORDS!
#if SB_UNROLL > 0
#define SB_UNROLL_WORDS(v, i, ...) do { \
    sb_bitcount_t v = (i); \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
    if (v < SB_FE_WORDS) { do __VA_ARGS__ while (0); } v++; \
} while (0)
#endif

#define SB_LOOP_WORDS(v, i, ...) \
    do { for (size_t v = (i); v < SB_FE_WORDS; v++) __VA_ARGS__ } while (0)

#if SB_UNROLL >= 1
#define SB_UNROLL_1(v, i, ...) SB_UNROLL_WORDS(v, i, __VA_ARGS__)
#else
#define SB_UNROLL_1(v, i, ...) SB_LOOP_WORDS(v, i, __VA_ARGS__)
#endif

#if SB_UNROLL >= 2
#define SB_UNROLL_2(v, i, ...) SB_UNROLL_WORDS(v, i, __VA_ARGS__)
#else
#define SB_UNROLL_2(v, i, ...) SB_LOOP_WORDS(v, i, __VA_ARGS__)
#endif

#if SB_UNROLL >= 3
#define SB_UNROLL_3(v, i, ...) SB_UNROLL_WORDS(v, i, __VA_ARGS__)
#else
#define SB_UNROLL_3(v, i, ...) SB_LOOP_WORDS(v, i, __VA_ARGS__)
#endif

typedef struct sb_fe_t {
    sb_word_t words[SB_FE_WORDS];
} sb_fe_t;

#define SB_FE_CONST(w3, w2, w1, w0) \
    { .words = { SB_WORD_EXPAND(UINT64_C(w0)), SB_WORD_EXPAND(UINT64_C(w1)), \
                 SB_WORD_EXPAND(UINT64_C(w2)), SB_WORD_EXPAND(UINT64_C(w3)) }}

#define SB_FE_WORD(fe, i) ((fe)->words[i])

static const sb_fe_t SB_FE_ONE = SB_FE_CONST(0, 0, 0, 1);
static const sb_fe_t SB_FE_ZERO = SB_FE_CONST(0, 0, 0, 0);

typedef struct sb_prime_field_t {
    sb_fe_t p;

    sb_word_t p_mp; // -(p^-1) mod M, where M is the size of sb_dword_t

    // Inversion mod p uses Fermat's little theorem: n^-1 == n^(p-2) mod p
    // Inversion does not need to be constant time with respect to the chosen
    // prime, and as such it's best to use exponents with a minimum Hamming
    // weight. Thus, we compute (n^f_1)^f_2 where (f_1 * f_2) = p - 2.
    // You can optimize inversion routines with more intermediate products
    // than this approach, but this works "well enough" for our purposes.
    sb_fe_t p_minus_two_f1; // used for Fermat's little theorem based inversion
    sb_fe_t p_minus_two_f2; // second factor of p - 2

    sb_fe_t r2_mod_p; // 2^(SB_FE_BITS * 2) mod p
    sb_fe_t r_mod_p; // 2^SB_FE_BITS mod p
    sb_bitcount_t bits; // the number of bits in the prime
} sb_prime_field_t;

extern void sb_fe_from_bytes(sb_fe_t dest[static restrict 1],
                             const sb_byte_t src[static restrict SB_ELEM_BYTES],
                             sb_data_endian_t e);

extern void sb_fe_to_bytes(sb_byte_t dest[static restrict SB_ELEM_BYTES],
                           const sb_fe_t src[static restrict 1],
                           sb_data_endian_t e);

extern sb_word_t sb_fe_equal(const sb_fe_t left[static 1],
                             const sb_fe_t right[static 1]);

extern sb_word_t sb_fe_test_bit(const sb_fe_t a[static 1], sb_bitcount_t bit);

extern void sb_fe_set_bit(sb_fe_t a[static 1], sb_bitcount_t bit, sb_word_t v);

extern sb_word_t sb_fe_add(sb_fe_t dest[static 1],
                           const sb_fe_t left[static 1],
                           const sb_fe_t right[static 1]);

extern sb_word_t sb_fe_sub(sb_fe_t dest[static 1],
                           const sb_fe_t left[static 1],
                           const sb_fe_t right[static 1]);

extern void sb_fe_qr(sb_fe_t dest[static restrict 1], sb_word_t carry,
                     const sb_prime_field_t p[static restrict 1]);

extern sb_word_t sb_fe_lt(const sb_fe_t left[static 1],
                          const sb_fe_t right[static 1]);

extern void sb_fe_ctswap(sb_word_t a,
                         sb_fe_t b[static restrict 1],
                         sb_fe_t c[static restrict 1]);

extern void sb_fe_mod_sub(sb_fe_t dest[static 1],
                          const sb_fe_t left[static 1],
                          const sb_fe_t right[static 1],
                          const sb_prime_field_t p[static 1]);

extern void sb_fe_mod_add(sb_fe_t dest[static 1],
                          const sb_fe_t left[static 1],
                          const sb_fe_t right[static 1],
                          const sb_prime_field_t p[static 1]);

extern void sb_fe_mod_double(sb_fe_t dest[static 1],
                             const sb_fe_t left[static 1],
                             const sb_prime_field_t p[static 1]);

extern void sb_fe_mont_mult(sb_fe_t dest[static restrict 1],
                            const sb_fe_t left[static 1],
                            const sb_fe_t right[static 1],
                            const sb_prime_field_t p[static 1]);

extern void sb_fe_mont_square(sb_fe_t dest[static restrict 1],
                              const sb_fe_t left[static 1],
                              const sb_prime_field_t p[static 1]);

extern void sb_fe_mont_reduce(sb_fe_t dest[static restrict 1],
                              const sb_fe_t left[static 1],
                              const sb_prime_field_t p[static 1]);

extern void sb_fe_mod_inv_r(sb_fe_t dest[static restrict 1],
                            sb_fe_t t2[static restrict  1],
                            sb_fe_t t3[static restrict  1],
                            const sb_prime_field_t p[static restrict 1]);

#endif
