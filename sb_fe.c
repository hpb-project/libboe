/*
 * sb_fe.c: constant time prime-field element operations
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
#include "sb_sw_curves.h"

// ARM assembly is provided for Thumb-2 and 32-bit ARMv6 and later targets.
// If you have DSP extensions, the UMAAL instruction is used, which provides
// substantially better multiplication performance. The following bit of
// preprocessor crud tests whether you have a target for which the assembly
// is supported. If this does not work for you (you're not getting assembly
// on a target where you expect it or the assembly generated does not work
// for your target), you can define SB_USE_ARM_ASM explicitly, but please
// also file a GitHub issue!

#ifndef SB_USE_ARM_ASM
#if (defined(__thumb__) && defined(__ARM_ARCH_ISA_THUMB) && \
     __ARM_ARCH_ISA_THUMB >= 2) || \
    (!defined(__thumb__) && defined(__ARM_ARCH) && __ARM_ARCH >= 6 && \
     !defined(__aarch64__)) && \
    SB_MUL_SIZE == 4
#define SB_USE_ARM_ASM 1
#if defined(__ARM_FEATURE_DSP) && !defined(SB_USE_ARM_DSP_ASM)
#define SB_USE_ARM_DSP_ASM 1
#endif
#else
#define SB_USE_ARM_ASM 0
#endif
#endif

#if !defined(SB_USE_ARM_DSP_ASM)
#define SB_USE_ARM_DSP_ASM 0
#endif

#if SB_USE_ARM_DSP_ASM && !SB_USE_ARM_ASM
#error "Conflicting options: SB_USE_ARM_DSP_ASM implies SB_USE_ARM_ASM"
#endif

// Convert an appropriately-sized set of bytes (src) into a field element
// using the given endianness.
void sb_fe_from_bytes(sb_fe_t dest[static const restrict 1],
                      const sb_byte_t src[static const restrict SB_ELEM_BYTES],
                      const sb_data_endian_t e)
{
    sb_wordcount_t src_i = 0;
    if (e == SB_DATA_ENDIAN_LITTLE) {
        src_i = SB_ELEM_BYTES - 1;
    }
    for (sb_wordcount_t i = 0; i < SB_FE_WORDS; i++) {
        sb_word_t t = 0;
        for (sb_wordcount_t j = 0; j < (SB_WORD_BITS / 8); j++) {
#if SB_MUL_SIZE != 1
            t <<= (sb_word_t) 8;
#endif
            t |= src[src_i];
            if (e == SB_DATA_ENDIAN_LITTLE) {
                src_i--;
            } else {
                src_i++;
            }
        }
        SB_FE_WORD(dest, SB_FE_WORDS - 1 - i) = t;
    }
}

// Convert a field element into bytes using the given endianness.
void sb_fe_to_bytes(sb_byte_t dest[static const restrict SB_ELEM_BYTES],
                    const sb_fe_t src[static const restrict 1],
                    const sb_data_endian_t e)
{
    sb_wordcount_t dest_i = 0;
    if (e == SB_DATA_ENDIAN_LITTLE) {
        dest_i = SB_ELEM_BYTES - 1;
    }
    for (sb_wordcount_t i = 0; i < SB_FE_WORDS; i++) {
        sb_word_t t = SB_FE_WORD(src, SB_FE_WORDS - 1 - i);
        for (sb_wordcount_t j = 0; j < (SB_WORD_BITS / 8); j++) {
            dest[dest_i] = (sb_byte_t) (t >> (SB_WORD_BITS - 8));
#if SB_MUL_SIZE != 1
            t <<= (sb_word_t) 8;
#endif
            if (e == SB_DATA_ENDIAN_LITTLE) {
                dest_i--;
            } else {
                dest_i++;
            }
        }
    }
}

// Returns an all-0 or all-1 word given a boolean flag 0 or 1 (respectively)
static inline sb_word_t sb_word_mask(const sb_word_t a)
{
    SB_ASSERT((a == 0 || a == 1), "word used for ctc must be 0 or 1");
    return (sb_word_t) -a;
}

// Used to select one of b or c in constant time, depending on whether a is 0 or 1
// ctc is an abbreviation for "constant time choice"
static inline sb_word_t sb_ctc_word(const sb_word_t a,
                                    const sb_word_t b,
                                    const sb_word_t c)
{
    return (sb_word_t) ((sb_word_mask(a) & (b ^ c)) ^ b);
}

sb_word_t sb_fe_equal(const sb_fe_t left[static const 1],
                      const sb_fe_t right[static const 1])
{
    sb_word_t r = 0;
    SB_UNROLL_3(i, 0, {
        // Accumulate any bit differences between left_i and right_i into r
        // using bitwise OR
        r |= SB_FE_WORD(left, i) ^ SB_FE_WORD(right, i);
    });
    // r | -r has bit SB_WORD_BITS - 1 set if r is nonzero
    // v ^ 1 is logical negation
    return ((r | ((sb_word_t) -r)) >> (sb_word_t) (SB_WORD_BITS - 1)) ^
           (sb_word_t) 1;
}

// Returns 1 if the bit is set, 0 otherwise
sb_word_t
sb_fe_test_bit(const sb_fe_t a[static const 1], const sb_bitcount_t bit)
{
    const size_t word = bit >> SB_WORD_BITS_SHIFT;
    return ((SB_FE_WORD(a, word) >> (bit & SB_WORD_BITS_MASK)) & (sb_word_t) 1);
}

// Set the given bit in the word to the value v (which must be 0 or 1)
void sb_fe_set_bit(sb_fe_t a[static const 1], const sb_bitcount_t bit,
                   const sb_word_t v)
{
    SB_ASSERT((v == 0 || v == 1), "word used for sb_fe_set_bit must be 0 or 1");
    const size_t word = bit >> SB_WORD_BITS_SHIFT;
    sb_word_t w = SB_FE_WORD(a, word);
    w &= ~((sb_word_t) 1 << (bit & SB_WORD_BITS_MASK));
    w |= (v << (bit & SB_WORD_BITS_MASK));
    SB_FE_WORD(a, word) = w;
}

#ifdef SB_TEST

// bits must be < SB_WORD_BITS
// as used, this is one or two
static void sb_fe_rshift_w(sb_fe_t a[static const 1], const sb_bitcount_t bits)
{
    sb_word_t carry = 0;
    for (size_t i = SB_FE_WORDS - 1; i <= SB_FE_WORDS; i--) {
        sb_word_t word = SB_FE_WORD(a, i);
        SB_FE_WORD(a, i) = (word >> bits) | carry;
        carry = (sb_word_t) (word << (SB_WORD_BITS - bits));
    }
}

static void sb_fe_rshift(sb_fe_t a[static const 1], sb_bitcount_t bits)
{
    while (bits > SB_WORD_BITS) {
        sb_word_t carry = 0;
        for (size_t i = SB_FE_WORDS - 1; i <= SB_FE_WORDS; i--) {
            sb_word_t word = SB_FE_WORD(a, i);
            SB_FE_WORD(a, i) = carry;
            carry = word;
        }
        bits -= SB_WORD_BITS;
    }
    sb_fe_rshift_w(a, bits);
}

#endif

// Add the given field elements and store the result in dest, which MAY alias
// left or right. The carry is returned.
sb_word_t sb_fe_add(sb_fe_t dest[static const 1],
                    const sb_fe_t left[static const 1],
                    const sb_fe_t right[static const 1])
{
    sb_word_t carry = 0;

#if SB_USE_ARM_ASM
    // ADD_ITER loads two words of left and two words of right, performs the
    // addition, and stores the result into dest. Stores are interleaved
    // with additions because on the Cortex-M4, there is a single-word
    // write buffer that allows a store to complete in one cycle if it is
    // followed by a non-memory operation.

    // add_0 is "adds" (do not consume carry flag in CPSR, but update it) on
    // the first addition and "adcs" subsequently (consume and update carry
    // flag).

    // Pseudocode:
    // l_0 = left[i_0]
    // l_1 = left[i_1]
    // r_0 = right[i_0]
    // r_1 = right[i_1]
    // if i_0 == 0 then (carry, l_0) = l_0 + r_0
    //             else (carry, l_0) = l_0 + r_0 + carry
    // dest[i_0] = l_0
    // (carry, l_1) = l_1 + r_1 + carry
    // dest[i_1] = l_1

    // l_0 is r4, l_1 is r5, r_0 is r6, r_1 is r7

#define ADD_ITER(add_0, i_0, i_1) \
          "ldrd r4, r5, [%[left], #" i_0 "]\n\t" \
          "ldrd r6, r7, [%[right], #" i_0 "]\n\t" \
          add_0 " r4, r4, r6\n\t" \
          "str  r4, [%[dest], #" i_0 "]\n\t" \
          "adcs r5, r5, r7\n\t" \
          "str  r5, [%[dest], #" i_1 "]\n\t" \

    __asm(ADD_ITER("adds", "0", "4")   // words 0 and 1
          ADD_ITER("adcs", "8", "12")  // words 2 and 3
          ADD_ITER("adcs", "16", "20") // words 4 and 5
          ADD_ITER("adcs", "24", "28") // words 6 and 7

          "adc  %[carry], %[carry], #0\n\t" // move C into carry

          : [carry] "+&r" (carry), "=m" (*dest)
          : [left] "r" (left), [right] "r" (right), [dest] "r" (dest),
            "m" (*left), "m" (*right)
          : "r4", "r5", "r6", "r7", "cc");

#else
    SB_UNROLL_2(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) +
                             (sb_dword_t) SB_FE_WORD(right, i) +
                             (sb_dword_t) carry;
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        carry = (sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
    return carry;
}

// Subtract the given field elements and store the result in dest, which MAY
// alias left or right. The borrow is returned.
static sb_word_t sb_fe_sub_borrow(sb_fe_t dest[static const 1],
                                  const sb_fe_t left[static const 1],
                                  const sb_fe_t right[static const 1],
                                  sb_word_t borrow)
{

#if SB_USE_ARM_ASM

    // SUB_ITER loads two words of left and two words of right and performs
    // the subtraction. The two arguments s_0 and s_1 are used for stores
    // where necessary; see sb_fe_lt for the case where the borrow is
    // computed but no stores are performed. See sb_fe_add for notes on the
    // store interleaving.

    // On ARM, the carry flag is the logical negation of the borrow flag; in
    // other words, if no borrow is needed, the carry flag is set.

    // Because this routine accepts an incoming borrow, the carry flag is
    // used on the first operation. In sb_fe_lt, it is not.

    // Pseudocode:
    // l_0 = left[i_0]
    // l_1 = left[i_1]
    // r_0 = right[i_0]
    // r_1 = right[i_1]
    // (carry, l_0) = l_0 - (r_0 + !carry)
    // dest[i_0] = l_0
    // (carry, l_1) = l_1 - (r_1 + !carry)
    // dest[i_1] = l_1

    // l_0 is r4, l_1 is r5, r_0 is r6, r_1 is r7

#define SUB_ITER(sub_0, s_0, s_1, i) \
          "ldrd r4, r5, [%[left], # " i "]\n\t" \
          "ldrd r6, r7, [%[right], # " i "]\n\t" \
          sub_0 " r4, r4, r6\n\t" \
          s_0 \
          "sbcs r5, r5, r7\n\t" \
          s_1

#define SUB_ITER_STORE(sub_0, i_0, i_1) \
          SUB_ITER(sub_0, "str r4, [%[dest], #" i_0 "]\n\t", \
                          "str r5, [%[dest], #" i_1 "]\n\t", i_0)


          // SUB_SET_B sets the value of the register b based on the borrow
          // using two instructions.

          // sbc b, b, b => b = b - (b + !carry)
          // simplifies to b = -!carry
          // if there was a borrow on the final subtraction: carry = 0, b = -1
          // if there was no borrow: carry = 1, b = 0

          // rsb b, 0 => b = 0 - b
          // if there was a borrow on the final subtraction, b = 1
          // if there was no borrow, b = 0
#define SUB_SET_B \
          "sbc  %[b], %[b], %[b]\n\t" \
          "rsb  %[b], #0\n\t"

          // Set the carry flag based on the incoming borrow: (carry, b) = 0 - b
    __asm("rsbs %[b], #0\n\t"


          SUB_ITER_STORE("sbcs", "0", "4")   // words 0 and 1
          SUB_ITER_STORE("sbcs", "8", "12")  // words 2 and 3
          SUB_ITER_STORE("sbcs", "16", "20") // words 4 and 5
          SUB_ITER_STORE("sbcs", "24", "28") // words 6 and 7

          SUB_SET_B

          : [b] "+&r" (borrow), "=m" (*dest)
          : [left] "r" (left), [right] "r" (right), [dest] "r" (dest),
            "m" (*left), "m" (*right) : "r4", "r5", "r6", "r7", "cc");

#else
    SB_UNROLL_2(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) -
                             ((sb_dword_t) SB_FE_WORD(right, i) +
                              (sb_dword_t) borrow);
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
    return borrow;
}


sb_word_t sb_fe_sub(sb_fe_t dest[static const 1],
                    const sb_fe_t left[static const 1],
                    const sb_fe_t right[static const 1])
{
    return sb_fe_sub_borrow(dest, left, right, 0);
}

sb_word_t sb_fe_lt(const sb_fe_t left[static 1],
                   const sb_fe_t right[static 1])
{
    sb_word_t borrow = 0;

#if SB_USE_ARM_ASM

    // See sb_fe_sub_borrow for the definition of SUB_ITER. The subtraction
    // here is used to compute the final borrow; no stores are performed.

    // Pseudocode:
    // l_0 = left[i_0]
    // l_1 = left[i_1]
    // r_0 = right[i_0]
    // r_1 = right[i_1]
    // if i_0 == 0 then (carry, l_0) = l_0 - r_0
    //             else (carry, l_0) = l_0 - (r_0 + !carry)
    // (carry, l_1) = l_1 - (r_1 + !carry)

    __asm(SUB_ITER("subs", "", "", "0")  // words 0 and 1
          SUB_ITER("sbcs", "", "", "8")  // words 2 and 3
          SUB_ITER("sbcs", "", "", "16") // words 4 and 5
          SUB_ITER("sbcs", "", "", "24") // words 6 and 7

          // see sb_fe_sub_borrow for notes on SUB_SET_B
          SUB_SET_B

          : [b] "+&r" (borrow)
          : [left] "r" (left), [right] "r" (right),
            "m" (*left), "m" (*right) : "r4", "r5", "r6", "r7", "cc");
#else
    SB_UNROLL_3(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(left, i) -
                             ((sb_dword_t) SB_FE_WORD(right, i) +
                              (sb_dword_t) borrow);
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
    return borrow;
}

// As a ZVA countermeasure, modular operations work with "quasi-reduced" inputs
// and outputs:
// Rather than reducing to [0, M - 1], they reduce to [1, M].
// While 0 may appear as an intermediary due to the borrow/carry implementation,
// Z blinding (Coron's third countermeasure) should ensure that an attacker
// can't cause such an intermediary product deliberately.

// This applies to P-256; for secp256k1, there is no (0, Y) point on the curve.
// Similarly, for curve25519, zero values will only occur when dealing with
// a small-order subgroup of the curve. Fortuitously (or not?), P-256's prime
// has a Hamming weight very close to 256/2, which makes analyses more
// difficult, though the zero limbs might still be detectable. During
// Montgomery multiplication of a Hamming-weight-128 field element by P, most
// of the intermediaries have hamming weight close to the original, with P
// only emerging in the last iteration of the loop.

// This helper routine subtracts p if c is 1; the subtraction is done
// unconditionally, and the result is only written if c is 1
static void sb_fe_cond_sub_p(sb_fe_t dest[static const restrict 1],
                             sb_word_t c,
                             const sb_fe_t p[static const restrict 1])
{
#if SB_USE_ARM_ASM

    c = sb_word_mask(c);

    // On ARM processors with the DSP extension, the SEL instruction is used
    // for constant-time selection. Otherwise, an exclusive-or / and /
    // exclusive-or sequence is used. SEL selects based on the GE bits in the
    // CPSR, which are set when certain instructions overflow. Since the
    // condition has been converted into a mask, adding the condition to
    // itself will always overflow.

#if SB_USE_ARM_DSP_ASM

    // set GE bits by adding the condition to itself
#define SB_COND_STORE_SET "uadd8 r4, %[c], %[c]\n\t"

    // Selects r into l if-and-only-if c
#define SB_COND_STORE_SEL(l, r, c) "sel " l ", " r ", " l "\n\t"

#else

#define SB_COND_STORE_SET ""

    // r = l ^ r
    // r = r & c
    // l = l ^ r
    // --> l = l ^ ((l ^ r) & c)
    // --> l = l if not C, r if C
#define SB_COND_STORE_SEL(l, r, c) \
          "eor  " r ", " l ", " r "\n\t" \
          "and  " r ", " r ", " c "\n\t" \
          "eor  " l ", " l ", " r "\n\t" \

#endif

    // See sb_fe_add for notes on store interleaving in the following.
    // SB_ITER_COND_STORE is used for conditional subtraction and conditional
    // addition of p.

    // Pseudocode:
    // l_0 = dest[i_0]
    // l_1 = dest[i_1]
    // r_0 = p[i_0]
    // r_1 = p[i_1]
    // if i_0 == 0 then (carry, r_0) = l_0 - r_0
    //             else (carry, r_0) = l_0 - (r_0 + !carry)
    // in constant time: if C then l_0 = r_0
    // dest[i_0] = l_0
    // (carry, r_1) = l_1 - (r_1 + !carry)
    // in constant time: if C then l_1 = r_1
    // dest[i_1] = l_1

    // l_0 is r4, l_1 is r5, r_0 is r6, r_1 is r7

#define SB_ITER_COND_STORE(ops, opcs, i_0, i_1) \
          "ldrd  r4, r5, [%[dest], #" i_0 "]\n\t" \
          "ldrd  r6, r7, [%[p], #" i_0 "]\n\t" \
          ops  " r6, r4, r6\n\t" \
          opcs " r7, r5, r7\n\t" \
          SB_COND_STORE_SEL("r4", "r6", "c") \
          "str   r4, [%[dest], #" i_0 "]\n\t" \
          SB_COND_STORE_SEL("r5", "r7", "c") \
          "str   r5, [%[dest], #" i_1 "]\n\t" \

    __asm(SB_COND_STORE_SET

          SB_ITER_COND_STORE("subs", "sbcs", "0", "4")   // words 0 and 1
          SB_ITER_COND_STORE("sbcs", "sbcs", "8", "12")  // words 2 and 3
          SB_ITER_COND_STORE("sbcs", "sbcs", "16", "20") // words 4 and 5
          SB_ITER_COND_STORE("sbcs", "sbcs", "24", "28") // words 6 and 7

          : "=m" (*dest)
          : [dest] "r" (dest), [p] "r" (p), [c] "r" (c),
            "m" (*dest), "m" (*p) : "r4", "r5", "r6", "r7", "cc");

#else
    sb_word_t borrow = 0;

    SB_UNROLL_2(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(dest, i) -
                             ((sb_dword_t) SB_FE_WORD(p, i) +
                              (sb_dword_t) borrow);
        SB_FE_WORD(dest, i) = sb_ctc_word(c, SB_FE_WORD(dest, i),
                                          (sb_word_t) d);
        borrow = (sb_word_t) -(sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
}

// Quasi-reduce dest (with extra carry bit) by subtracting p iff dest is
// greater than p
void sb_fe_qr(sb_fe_t dest[static const restrict 1],
              sb_word_t const carry,
              const sb_prime_field_t p[static const restrict 1])
{
    sb_word_t b = sb_fe_lt(&p->p, dest);
    sb_fe_cond_sub_p(dest, carry | b, &p->p);
    SB_ASSERT(sb_fe_equal(dest, &p->p) || sb_fe_lt(dest, &p->p),
              "quasi-reduction must always produce quasi-reduced output");
    SB_ASSERT(!sb_fe_equal(dest, &SB_FE_ZERO),
              "quasi-reduction must always produce quasi-reduced output");
}

// This helper adds 1 or (p + 1), depending on c. On ARM, this is done by
// adding p then choosing to store either the original value or the result of
// the addition, followed by a second pass to add 1.
static void sb_fe_cond_add_p_1(sb_fe_t dest[static const restrict 1],
                               sb_word_t c,
                               const sb_fe_t p[static const restrict 1])
{
#if SB_USE_ARM_ASM

    c = sb_word_mask(c);

    // ADD_1_ITER is used to add 1 to dest. See sb_fe_add for notes on store
    // interleaving.

    // Pseudocode:
    // l_0 = dest[i_0]
    // l_1 = dest[i_1]
    // if i_0 == 0 then (carry, l_0) = l_0 + 1
    //             else (carry, l_0) = l_0 + carry
    // dest[i_0] = l_0
    // (carry, l_1) = l_1 + carry
    // dest[i_1] = l_1

    // l_0 is r4, l_1 is r5

#define ADD_1_ITER(add_0, add_0_v, i_0, i_1) \
          "ldrd r4, r5, [%[dest], #" i_0 "]\n\t" \
          add_0 " r4, r4, #" add_0_v "\n\t" \
          "str  r4, [%[dest], #" i_0 "]\n\t" \
          "adcs r5, r5, #0\n\t" \
          "str  r5, [%[dest], #" i_1 "]\n\t"

    // Here SB_ITER_COND_STORE is used to add p.

    // Pseudocode:
    // l_0 = dest[i_0]
    // l_1 = dest[i_1]
    // r_0 = p[i_0]
    // r_1 = p[i_1]
    // if i_0 == 0 then (carry, r_0) = l_0 + r_0
    //             else (carry, r_0) = l_0 + r_0 + carry
    // in constant time: if C then l_0 = r_0
    // dest[i_0] = l_0
    // (carry, r_1) = l_1 + r_1 + carry
    // in constant time: if C then l_1 = r_1
    // dest[i_1] = l_1

    __asm(SB_COND_STORE_SET

          SB_ITER_COND_STORE("adds", "adcs", "0", "4")   // words 0 and 1
          SB_ITER_COND_STORE("adcs", "adcs", "8", "12")  // words 2 and 3
          SB_ITER_COND_STORE("adcs", "adcs", "16", "20") // words 4 and 5
          SB_ITER_COND_STORE("adcs", "adcs", "24", "28") // words 6 and 7

          ADD_1_ITER("adds", "1", "0", "4")   // words 0 and 1
          ADD_1_ITER("adcs", "0", "8", "12")  // words 2 and 3
          ADD_1_ITER("adcs", "0", "16", "20") // words 4 and 5
          ADD_1_ITER("adcs", "0", "24", "28") // words 6 and 7

          : "=m" (*dest)
          : [dest] "r" (dest), [p] "r" (p), [c] "r" (c),
            "m" (*dest), "m" (*p) : "r4", "r5", "r6", "r7", "cc");

#else
    sb_word_t carry = 1;

    SB_UNROLL_2(i, 0, {
        const sb_dword_t d = (sb_dword_t) SB_FE_WORD(dest, i) +
                             (sb_dword_t) sb_ctc_word(c, 0, SB_FE_WORD(p, i)) +
                             (sb_dword_t) carry;
        SB_FE_WORD(dest, i) = (sb_word_t) d;
        carry = (sb_word_t) (d >> SB_WORD_BITS);
    });
#endif
}


// Given quasi-reduced left and right, produce quasi-reduced left - right.
// This is done as a subtraction of (right - 1) followed by addition of
// 1 or (p + 1), which means that a result of all zeros is never written back
// to memory.
void
sb_fe_mod_sub(sb_fe_t dest[static const 1],
              const sb_fe_t left[static const 1],
              const sb_fe_t right[static const 1],
              const sb_prime_field_t p[static const 1])
{
    const sb_word_t b = sb_fe_sub_borrow(dest, left, right, 1);
    sb_fe_cond_add_p_1(dest, b, &p->p);
    SB_ASSERT(sb_fe_equal(dest, &p->p) || sb_fe_lt(dest, &p->p),
              "modular subtraction must always produce quasi-reduced output");
    SB_ASSERT(!sb_fe_equal(dest, &SB_FE_ZERO),
              "modular subtraction must always produce quasi-reduced output");
}

// Given quasi-reduced left and right, produce quasi-reduced left + right.

void
sb_fe_mod_add(sb_fe_t dest[static const 1], const sb_fe_t left[static const 1],
              const sb_fe_t right[static const 1],
              const sb_prime_field_t p[static const 1])
{
    sb_word_t carry = sb_fe_add(dest, left, right);
    sb_fe_qr(dest, carry, p);
}

void sb_fe_mod_double(sb_fe_t dest[static const 1],
                      const sb_fe_t left[static const 1],
                      const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_add(dest, left, left, p);
}

#ifdef SB_TEST

_Bool sb_test_fe(void)
{
    sb_fe_t res;
    SB_TEST_ASSERT(sb_fe_sub(&res, &SB_FE_ZERO, &SB_FE_ONE) == 1);
    for (size_t i = 0; i < SB_FE_WORDS; i++) {
        SB_TEST_ASSERT(SB_FE_WORD(&res, i) == (sb_word_t) -1);
    }
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &SB_FE_ONE) == 1);
    SB_TEST_ASSERT(sb_fe_equal(&res, &SB_FE_ZERO));

    // all 0xFF
    SB_TEST_ASSERT(sb_fe_sub(&res, &SB_FE_ZERO, &SB_FE_ONE) == 1);
    sb_fe_rshift(&res, 1);
    // 0xFFFF.....FFFE
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &res) == 0);
    // 0xFFFF.....FFFF
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &SB_FE_ONE) == 0);
    // 0
    SB_TEST_ASSERT(sb_fe_add(&res, &res, &SB_FE_ONE) == 1);
    SB_TEST_ASSERT(sb_fe_equal(&res, &SB_FE_ZERO));
    return 1;
}

#endif

// This helper is the equivalent of a single ARM DSP instruction:
// (h, l) = a * b + c + d
static inline void sb_mult_add_add(sb_word_t h[static const restrict 1],
                                   sb_word_t l[static const restrict 1],
                                   const sb_word_t a,
                                   const sb_word_t b,
                                   const sb_word_t c,
                                   const sb_word_t d)
{
#if SB_USE_ARM_DSP_ASM
    register sb_word_t h_dest = c;
    register sb_word_t l_dest = d;
    __asm("umaal %0, %1, %2, %3" : "+r" (l_dest), "+r" (h_dest) : "r" (a), "r" (b));
    *h = h_dest;
    *l = l_dest;
#else
    const sb_dword_t t =
        ((sb_dword_t) a * (sb_dword_t) b) + (sb_dword_t) c + (sb_dword_t) d;
    *h = (sb_word_t) (t >> (SB_WORD_BITS));
    *l = (sb_word_t) t;
#endif
}

static inline void sb_add_carry_2(sb_word_t h[static const restrict 1],
                                  sb_word_t l[static const restrict 1],
                                  const sb_word_t a,
                                  const sb_word_t b,
                                  const sb_word_t c)
{
    const sb_dword_t r = (sb_dword_t) a + (sb_dword_t) b + (sb_dword_t) c;
    *h = (sb_word_t) (r >> SB_WORD_BITS);
    *l = (sb_word_t) r;
}

// Montgomery multiplication: given x, y, p produces x * y * R^-1 mod p where
// R = 2^256 mod p. See the _Handbook of Applied Cryptography_ by Menezes,
// van Oorschot, and Vanstone, chapter 14, section 14.3.2:
// http://cacr.uwaterloo.ca/hac/about/chap14.pdf
void sb_fe_mont_mult(sb_fe_t A[static const restrict 1],
                     const sb_fe_t x[static const 1],
                     const sb_fe_t y[static const 1],
                     const sb_prime_field_t p[static const 1])
{
#if SB_USE_ARM_DSP_ASM && SB_UNROLL > 0

    // If SB_UNROLL is 3, then the outer multiplication loop is fully unrolled.
    // Otherwise, only the inner loop is unrolled.

    sb_word_t hw, c, c2, x_i, u_i;

#if SB_UNROLL < 3
    sb_word_t i;
#endif

    // MM_ITER_MUL performs one round of the inner Montgomery-multiplication
    // loop. On the very first iteration, A is 0, so A_0 and A_1 are used to
    // set A_j_0 and A_j_1 to 0 or to load A depending on the iteration.
    // The expression e is used to compute u_i when j is 0.
    // s_0 and s_1 are used to store A. See sb_fe_add for notes about store
    // interleaving. Additionally, to implement the division-by-b step, the
    // first store is omitted and following stores write to an address of
    // A + (j - 4) where the offset is computed in bytes.

    // Pseudocode for MM_ITER_MUL(i, j) where i and j are in byte offsets:

    // y_j_0 = y[j]
    // y_j_1 = y[j + 4]
    // if i == 0, then A_j_0 = 0
    //            else A_j_0 = A[j]
    // if i != 0, then A_j_1 = A[j + 4]
    // (c, A_j_0) = x_i * y_j_0 + A_j_0 + c
    // if i == 0, then A_j_1 = 0
    // (c, A_j_1) = x_i * y_j_1 + A_j_1 + c
    // if j == 0, then u_i = A_j_0 * p->mp
    // y_j_0 = p[j]
    // y_j_1 = p[j + 4]
    // (c2, A_j_0) = u_i * y_j_0 + A_j_0 + c2
    // if i != 0, A[j - 4] = A_j_0
    // (c2, A_j_1) = u_i * y_j_1 + A_j_1 + c2
    // A[j] = A_j_1

    // A_j_0 is r4, A_j_1 is r5, y_j_0 is r6, y_j_1 is r7

#define MM_ITER_MUL(A_0, A_1, j, e, s_0, s_1) \
        "ldrd  r6, r7, [%[y], #" j "]\n\t" \
        A_0 \
        "umaal r4, %[c], %[x_i], r6\n\t" \
        A_1 \
        "umaal r5, %[c], %[x_i], r7\n\t" \
        e \
        "ldrd  r6, r7, [%[p], #" j "]\n\t" \
        "umaal r4, %[c2], %[u_i], r6\n\t" \
        s_0 \
        "umaal r5, %[c2], %[u_i], r7\n\t" \
        s_1

    // When i == 0, A is 0
#define MM_ITER_1_I(j, e, s_0, s_1) \
        MM_ITER_MUL("mov r4, #0\n\t", "mov r5, #0\n\t", \
                   j, e, s_0, s_1)

    // Otherwise, A must be loaded into A_j_0 and A_j_1
#define MM_ITER_2_I(j, e, s_0, s_1) \
        MM_ITER_MUL("ldrd r4, r5, [%[A], #" j "]\n\t", "", \
                    j, e, s_0, s_1)

    // Pseudocode for MM_ITER(i) where i is in byte offsets:
    // c = 0
    // c2 = 0
    // x_i = x[i]
    // MM_ITER_MUL(i, 0)
    // MM_ITER_MUL(i, 8)
    // MM_ITER_MUL(i, 16)
    // MM_ITER_MUL(i, 24)
    // if i == 0, then (carry, A_j_0) = c + c2
    //            else (carry, A_j_0) = c + c2 + carry
    // A[28] = A_j_0

    // add is adds when i is 0 and adcs otherwise

#define MM_ITER(M, add, i) \
    "mov   %[c], #0\n\t" \
    "mov   %[c2], #0\n\t" \
    "ldr   %[x_i], [%[x], " i "]\n\t" \
    M("0", "mul %[u_i], r4, %[hw]\n\t", "", "str r5, [%[A]]\n\t") \
    M("8", "", "str r4, [%[A], #4]\n\t", \
               "str r5, [%[A], #8]\n\t") \
    M("16", "", "str r4, [%[A], #12]\n\t", \
                "str r5, [%[A], #16]\n\t") \
    M("24", "", "str r4, [%[A], #20]\n\t", \
                "str r5, [%[A], #24]\n\t") \
    add "  r4, %[c], %[c2]\n\t" \
    "str   r4, [%[A], #28]\n\t"

    // Pseudocode:
    // hw = p->mp
    // MM_ITER(0, 0)
    // for (i = 4; i < 32; i += 4) do MM_ITER(i)
    // hw = 0
    // hw = hw + 0 + carry

    // The first iteration is always unrolled because A is set to 0 on this iteration
    __asm(
    "ldr  %[hw], [%[p], #32]\n\t" // use hw as p->mp
    MM_ITER(MM_ITER_1_I, "adds", "#0")
#if SB_UNROLL < 3
    "mov %[i], #4\n\t"
    ".L_mont_mul_loop%=: " // %= introduces a unique-per-__asm-statement label
    MM_ITER(MM_ITER_2_I, "adcs", "%[i]")
    "add %[i], #4\n\t"
    "tst %[i], #32\n\t" // true when i & 32 is nonzero; does not affect carry flag
    "beq .L_mont_mul_loop%=\n\t"
#else
    MM_ITER(MM_ITER_2_I, "adcs", "#4")
    MM_ITER(MM_ITER_2_I, "adcs", "#8")
    MM_ITER(MM_ITER_2_I, "adcs", "#12")
    MM_ITER(MM_ITER_2_I, "adcs", "#16")
    MM_ITER(MM_ITER_2_I, "adcs", "#20")
    MM_ITER(MM_ITER_2_I, "adcs", "#24")
    MM_ITER(MM_ITER_2_I, "adcs", "#28")
#endif

    // move carry flag into hw: hw = 0; hw = hw + 0 + carry
    "mov %[hw], #0\n\t"
    "adc %[hw], %[hw], #0\n\t"
    : [c] "=&r" (c), [c2] "=&r" (c2),
      [u_i] "=&r" (u_i), [hw] "=&r" (hw),
#if SB_UNROLL < 3
      [i] "=&r" (i),
#endif
      [x_i] "=&r" (x_i), "=m" (*A)
    : [A] "r" (A), [y] "r" (y), [p] "r" (p), [x] "r" (x),
      "m" (*x), "m" (*y), "m" (*p) :
    "r4", "r5", "r6", "r7", "cc");

#else

    sb_word_t hw = 0;

    SB_UNROLL_2(i, 0, { // for i from 0 to (n - 1)
        const sb_word_t x_i = SB_FE_WORD(x, i);

        sb_word_t c = 0, c2 = 0;

        SB_UNROLL_1(j, 0, {
            // On the first iteration, A is 0
            const sb_word_t A_j = (i == 0) ? 0 : SB_FE_WORD(A, j);
            // A = A + x_i * y
            sb_mult_add_add(&c, &SB_FE_WORD(A, j), x_i, SB_FE_WORD(y, j),
            A_j, c);
        });

        // u_i = (a_0 + x_i y_0) m' mod b
        const sb_word_t u_i =
            (sb_word_t)
                (SB_FE_WORD(A, 0) *
                 ((sb_dword_t) p->p_mp));

        SB_UNROLL_1(j, 0, {
            // A = A + u_i * m
            sb_mult_add_add(&c2, &SB_FE_WORD(A, j), u_i,
                            SB_FE_WORD(&p->p, j), SB_FE_WORD(A, j),
                            c2);
        });

        // A = A / b
        SB_UNROLL_1(j, 1, { SB_FE_WORD(A, j - 1) = SB_FE_WORD(A, j); });

        sb_add_carry_2(&hw, &SB_FE_WORD(A, SB_FE_WORDS - 1), hw, c, c2);
        SB_ASSERT(hw < 2, "W + W * W + W * W overflows at most once");
    });

#endif

    // If A > p or hw is set, A = A - p

    sb_fe_qr(A, hw, p);
}

// Montgomery squaring: dest = left * left * R^-1 mod p
void sb_fe_mont_square(sb_fe_t dest[static const restrict 1],
                       const sb_fe_t left[static const 1],
                       const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(dest, left, left, p);
}

// Montgomery reduction: dest = left * R^-1 mod p, implemented by Montgomery
// multiplication by 1.
void sb_fe_mont_reduce(sb_fe_t dest[static const restrict 1],
                       const sb_fe_t left[static const 1],
                       const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(dest, left, &SB_FE_ONE, p);
}

#ifdef SB_TEST

_Bool sb_test_mont_mult(void)
{
    static const sb_fe_t p256_r_inv =
        SB_FE_CONST(0xFFFFFFFE00000003, 0xFFFFFFFD00000002,
                    0x00000001FFFFFFFE, 0x0000000300000000);
    sb_fe_t t = SB_FE_ZERO;

    sb_fe_t r = SB_FE_ZERO;
    SB_TEST_ASSERT(sb_fe_sub(&r, &r, &SB_CURVE_P256_P.p) == 1); // r = R mod P

    sb_fe_mont_square(&t, &SB_FE_ONE, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &p256_r_inv));
    // aka R^-1 mod P

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &r));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.r2_mod_p,
                    &p256_r_inv, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE));

    sb_fe_t t2;
    sb_fe_mont_mult(&t2, &SB_CURVE_P256_N.p, &SB_CURVE_P256_P.r2_mod_p,
                    &SB_CURVE_P256_P);
    sb_fe_mont_reduce(&t, &t2, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_N.p));

    r = SB_FE_ZERO;
    SB_TEST_ASSERT(sb_fe_sub(&r, &r, &SB_CURVE_P256_N.p) == 1); // r = R mod N
    SB_TEST_ASSERT(sb_fe_equal(&r, &SB_CURVE_P256_N.r_mod_p));

    sb_fe_mont_mult(&t, &SB_CURVE_P256_N.r2_mod_p, &SB_FE_ONE,
                    &SB_CURVE_P256_N);
    SB_TEST_ASSERT(sb_fe_equal(&t, &r));

    sb_fe_mont_mult(&t, &r, &SB_FE_ONE, &SB_CURVE_P256_N);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE));

    static const sb_fe_t a5 = SB_FE_CONST(0xAA55AA55AA55AA55,
                                          0x55AA55AA55AA55AA,
                                          0xAA55AA55AA55AA55,
                                          0x55AA55AA55AA55AA);

    sb_fe_mont_mult(&t, &SB_CURVE_P256_P.p, &a5,
                    &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_P.p));
    return 1;
}

#endif

// Swap `b` and `c if `a` is true using constant-time choice.
void sb_fe_ctswap(const sb_word_t a,
                  sb_fe_t b[static const restrict 1],
                  sb_fe_t c[static const restrict 1])
{
    for (size_t i = 0; i < SB_FE_WORDS; i++) {
        const sb_word_t t = sb_ctc_word(a, SB_FE_WORD(b, i), SB_FE_WORD(c, i));
        SB_FE_WORD(c, i) = sb_ctc_word(a, SB_FE_WORD(c, i), SB_FE_WORD(b, i));
        SB_FE_WORD(b, i) = t;
    }
}

// x = x^e mod m

// Modular exponentation is NOT constant time with respect to the exponent;
// this procedure is used ONLY for inversion (and possibly square roots in
// the future) and the exponents are determined by the prime in this case.
// It is assumed that performance may differ with respect to the curve, but
// not with respect to the inputs.

static void
sb_fe_mod_expt_r(sb_fe_t x[static const restrict 1],
                 const sb_fe_t e[static const restrict 1],
                 sb_fe_t t2[static const restrict 1],
                 sb_fe_t t3[static const restrict 1],
                 const sb_prime_field_t p[static const restrict 1])
{
    _Bool by = 0;
    *t2 = p->r_mod_p;
    for (size_t i = p->bits - 1; i <= SB_FE_BITS; i--) {
        const sb_word_t b = sb_fe_test_bit(e, i);
        if (!by) {
            if (b) {
                by = 1;
            } else {
                continue;
            }
        }
        sb_fe_mont_square(t3, t2, p);
        if (b) {
            sb_fe_mont_mult(t2, t3, x, p);
        } else {
            *t2 = *t3;
        }
    }
    *x = *t2;
}

// See sb_prime_field_t in sb_fe.h for more comments on modular inversion.
void sb_fe_mod_inv_r(sb_fe_t dest[static const restrict 1],
                     sb_fe_t t2[static const restrict 1],
                     sb_fe_t t3[static const restrict 1],
                     const sb_prime_field_t p[static const restrict 1])
{
    sb_fe_mod_expt_r(dest, &p->p_minus_two_f1, t2, t3, p);
    sb_fe_mod_expt_r(dest, &p->p_minus_two_f2, t2, t3, p);
}

#ifdef SB_TEST

static void
sb_fe_mod_expt(sb_fe_t x[static const 1], const sb_fe_t e[static const 1],
               sb_fe_t t2[static const 1], sb_fe_t t3[static const 1],
               const sb_prime_field_t p[static const 1])
{
    sb_fe_mont_mult(t2, x, &p->r2_mod_p, p);
    *x = *t2;
    sb_fe_mod_expt_r(x, e, t2, t3, p);
    sb_fe_mont_mult(t2, x, &SB_FE_ONE, p);
    *x = *t2;
}

static void sb_fe_mod_inv(sb_fe_t dest[static const 1],
                          sb_fe_t t2[static const 1],
                          sb_fe_t t3[static const 1],
                          const sb_prime_field_t p[static const 1])
{
    sb_fe_mod_expt(dest, &p->p_minus_two_f1, t2, t3, p);
    sb_fe_mod_expt(dest, &p->p_minus_two_f2, t2, t3, p);
}

_Bool sb_test_mod_expt_p(void)
{
    const sb_fe_t two = SB_FE_CONST(0, 0, 0, 2);
    const sb_fe_t thirtytwo = SB_FE_CONST(0, 0, 0, 32);
    const sb_fe_t two_expt_thirtytwo = SB_FE_CONST(0, 0, 0, 0x100000000);
    sb_fe_t t, t2, t3;
    t = two;
    sb_fe_mod_expt(&t, &thirtytwo, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &two_expt_thirtytwo));

    t = SB_CURVE_P256_N.p;
    sb_fe_mod_expt(&t, &SB_CURVE_P256_P.p, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^p == n

    t = SB_CURVE_P256_N.p;
    sb_fe_mod_expt(&t, &SB_FE_ONE, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_N.p)); // n^1 = n

    t = SB_CURVE_P256_P.p;
    sb_fe_sub(&t, &t, &SB_FE_ONE);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    sb_fe_add(&t, &t, &SB_FE_ONE);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_CURVE_P256_P.p)); // (p-1)^-1 == (p-1)

    t = SB_FE_ONE;
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t, &SB_FE_ONE)); // 1^-1 == 1

    // t = B * R^-1
    sb_fe_mont_mult(&t, &SB_CURVE_P256.b, &SB_FE_ONE, &SB_CURVE_P256_P);

    // t = B^-1 * R
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_P);

    // t2 = B^-1 * R * B * R^-1 = 1
    sb_fe_mont_mult(&t2, &t, &SB_CURVE_P256.b, &SB_CURVE_P256_P);
    SB_TEST_ASSERT(sb_fe_equal(&t2, &SB_FE_ONE));

    // and again, mod N
    sb_fe_mont_mult(&t, &SB_CURVE_P256.b, &SB_FE_ONE, &SB_CURVE_P256_N);
    sb_fe_mod_inv(&t, &t2, &t3, &SB_CURVE_P256_N);
    sb_fe_mont_mult(&t2, &t, &SB_CURVE_P256.b, &SB_CURVE_P256_N);
    SB_TEST_ASSERT(sb_fe_equal(&t2, &SB_FE_ONE));
    return 1;
}

#endif
