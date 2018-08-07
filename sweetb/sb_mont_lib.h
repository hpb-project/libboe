/*
 * sb_mont_lib.h: public API for operations on Montgomery elliptic curves
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

#ifndef SB_MONT_LIB_H
#define SB_MONT_LIB_H

#include "sb_fe.h"
#include "sb_hmac_drbg.h"
#include "sb_mont_context.h"

typedef sb_single_t sb_mont_private_t;
typedef sb_single_t sb_mont_public_t;
typedef sb_single_t sb_mont_shared_secret_t;

// While only one curve is currently supported, in the future this may be
// extended to explicitly allow using the quadratic twist of curve25519
typedef enum sb_mont_curve_id_value_t {
    SB_MONT_CURVE_25519 = 0,
#ifdef SB_TEST
    SB_MONT_CURVE_INVALID = 0x7FFFFFFF
#endif
} sb_mont_curve_id_value_t;

typedef uint32_t sb_mont_curve_id_t;

// All of the following methods take an initial parameter of type
// sb_mont_context_t. You are responsible for allocating this context
// structure. You may allocate different structures for each call or reuse
// the same structure multiple times. The context is small and may be stack
// allocated.

// All of the following functions return sb_error_t; see sb_types.h for the
// definition of the error type and sb_error.h for the error values returned.
// sb_error_t the bitwise or of multiple error values; you MUST test for
// specific error values by checking whether the appropriate bit is set in
// the return value. Two errors (CURVE_INVALID and RESEED_REQUIRED) are
// returned immediately, which is to say that no further computation is
// performed if either of these errors is true. If the function
// accepts a public key, it is checked before any futher computation.
// Otherwise, the function will run to completion in constant time with
// respect to the inputs; if the function produces output, the output
// returned will be junk if the return value is not SB_SUCCESS.

// For the only implemented Montgomery curve, there is no separate private
// key generation function supplied. Use sb_hmac_drbg_generate with a
// correctly seeded DRBG to generate SB_ELEM_BYTES of random data; any such
// data is a valid private key.

// sb_mont_compute_public_key:

// Returns the public key for the supplied private key. The drbg parameter is
// optional and is used for Z blinding. Fails if the curve specified is
// invalid or if the optionally supplied drbg requires reseeding.

extern sb_error_t sb_mont_compute_public_key
    (sb_mont_context_t context[static 1],
     sb_mont_public_t public[static 1],
     const sb_mont_private_t private[static 1],
     sb_hmac_drbg_state_t* drbg,
     sb_mont_curve_id_t curve);

// sb_mont_shared_secret:

// Generate an ECDH shared secret using the given private key and public key.
// You SHOULD use this shared secret as input to a key-derivation function
// (KDF) instead of using it directly. Selection of an appropriate KDF is
// application-specific and outside the scope of Sweet B; however, most
// hash-based KDFs are easily implemented using the supplied SHA256 and
// HMAC-SHA256 procedures. See RFC5869 for one such KDF scheme, and NIST
// SP800-56A rev. 2 for details on a single-step SHA256-based scheme.

// Fails if the supplied curve or public key is invalid, or if the
// optionally supplied drbg requires reseeding.

extern sb_error_t sb_mont_shared_secret
    (sb_mont_context_t context[static 1],
     sb_mont_shared_secret_t secret[static 1],
     const sb_mont_private_t private[static 1],
     const sb_mont_public_t public[static 1],
     sb_hmac_drbg_state_t* drbg,
     sb_mont_curve_id_t curve);

#endif
