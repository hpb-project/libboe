/*
 * sb_sha256.h: public API for SHA-256
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

#ifndef SB_SHA256_H
#define SB_SHA256_H

#include <stddef.h>
#include <stdint.h>
#include "sb_types.h"

#define SB_SHA256_SIZE 32
#define SB_SHA256_BLOCK_SIZE 64

typedef struct sb_sha256_ihash_t {
    uint32_t v[8];
} sb_sha256_ihash_t;

// Private state structure; you are responsible for allocating this and
// passing it in to sha256 operations
typedef struct sb_sha256_state_t {
    sb_sha256_ihash_t ihash; // Intermediate hash state
    sb_sha256_ihash_t a_h; // a through h, the working variables
    uint32_t W[16]; // message schedule rotating window
    sb_byte_t buffer[SB_SHA256_BLOCK_SIZE]; // Block-sized buffer of input
    size_t total_bytes; // Total number of bytes processed
} sb_sha256_state_t;

extern void sb_sha256_init(sb_sha256_state_t sha[static 1]);

extern void sb_sha256_update(sb_sha256_state_t sha[static restrict 1],
                             const sb_byte_t* restrict input,
                             size_t len);

extern void sb_sha256_finish(sb_sha256_state_t sha[static restrict 1],
                             sb_byte_t output[static restrict SB_SHA256_SIZE]);

#endif
