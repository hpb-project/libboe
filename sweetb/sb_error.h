/*
 * sb_error.h: multiply-included file defining Sweet B errors; see sb_types.h
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

#ifndef SB_ERROR_IMPL
#error "sb_error.h must not be included from outside sb_types.h"
#endif

// New entries in this list MUST be added at the end for ABI compatibility!

// The entropy input used to seed the DRBG is too small
SB_ERROR(INSUFFICIENT_ENTROPY)

// The input to the DRBG is too large
SB_ERROR(INPUT_TOO_LARGE)

// The DRBG generate request is too large
SB_ERROR(REQUEST_TOO_LARGE)

// The DRBG must be reseeded and the operation can be retried
SB_ERROR(RESEED_REQUIRED)

// The DRBG has produced an extremely low-probability output (p < 2^-64)
SB_ERROR(DRBG_FAILURE)

// The curve supplied is invalid
SB_ERROR(CURVE_INVALID)

// The supplied private key is invalid
SB_ERROR(PRIVATE_KEY_INVALID)

// The supplied public key is invalid
SB_ERROR(PUBLIC_KEY_INVALID)

// The signature is invalid
SB_ERROR(SIGNATURE_INVALID)
