/*
 * sb_types.h: public API for common types
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

#ifndef SB_TYPES_H
#define SB_TYPES_H

#include <stdint.h>

#define SB_ELEM_BYTES 32

// Used to indicate "a bunch of bytes" instead of "an 8-bit integer we're
// doing arithmetic on"
typedef uint8_t sb_byte_t;

typedef struct sb_single_t {
    sb_byte_t bytes[SB_ELEM_BYTES];
} sb_single_t;

typedef struct sb_double_t {
    sb_byte_t bytes[SB_ELEM_BYTES * 2];
} sb_double_t;

typedef enum sb_data_endian_value_t {
    SB_DATA_ENDIAN_LITTLE = 0,
    SB_DATA_ENDIAN_BIG
} sb_data_endian_value_t;

typedef uint32_t sb_data_endian_t;

// Functions which return errors in Sweet B may return a bitwise-or of multiple
// error values. For instance, when initializing a HMAC-DRBG instance, if the
// supplied entropy input is too small and the supplied personalization
// string is too large, the return value will be
// SB_ERROR_INSUFFICIENT_ENTROPY | SB_ERROR_INPUT_TOO_LARGE.

// See sb_error.h for the actual definitions of the errors. A definition such
// as SB_ERROR(INSUFFICIENT_ENTROPY) there will define a value
// SB_ERROR_INSUFFICIENT_ENTROPY which may be tested for with bitwise-and.

// TODO: is it worth making this uint64_t?
typedef uint32_t sb_error_t;

static const sb_error_t SB_SUCCESS = 0;

#define SB_ERROR_IMPL 1
#define SB_ERROR(name) SB_ERROR_SHIFT_ ## name ,
typedef enum sb_error_shift_t {
#include "sb_error.h"
} sb_error_shift_t;

#undef SB_ERROR

#define SB_ERROR(name) static const sb_error_t SB_ERROR_ ## name = \
    (UINT32_C(1) << SB_ERROR_SHIFT_ ## name);
#include "sb_error.h"
#undef SB_ERROR
#undef SB_ERROR_IMPL

#define SB_ERROR_IF(err, cond) (((sb_error_t) (cond)) << SB_ERROR_SHIFT_ ## err)

#define SB_RETURN_ERRORS_2(err, zero_ctx) do { \
    if (err) { \
        memset((zero_ctx), 0, sizeof(*(zero_ctx))); \
        return err; \
    } \
} while (0)

#define SB_RETURN_ERRORS_1(err, unused) do { \
    if (err) { \
        return err; \
    } \
} while (0)

#define SB_RETURN_ERRORS_n(a, b, c, ...) c(a, b)

#define SB_RETURN_ERRORS(...) \
    SB_RETURN_ERRORS_n(__VA_ARGS__, SB_RETURN_ERRORS_2, SB_RETURN_ERRORS_1, \
                       NOT_ENOUGH_ARGUMENTS)

#endif
