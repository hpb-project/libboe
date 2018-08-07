/*
 * sb_test.h: private API for Sweet B unit tests and debug assertions
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

#ifndef SB_TEST_H
#define SB_TEST_H

#if defined(SB_DEBUG_ASSERTS) || defined(SB_TEST)
#include <assert.h>
#define SB_ASSERT(e, s) assert((e) && (s)[0])
#else
#define SB_ASSERT(e, s) do { } while (0)
#endif

#ifdef SB_TEST
#include <stdio.h>
#include <string.h>

#ifndef SB_TEST_ITER_DEFAULT
#define SB_TEST_ITER_DEFAULT 8192
#endif

#define SB_TEST_STRINGIFY_E(e) #e
#define SB_TEST_STRINGIFY(e) SB_TEST_STRINGIFY_E(e)

#define SB_TEST_ASSERT(e) do { \
    if (!(e)) { \
        printf("\n" __FILE__ ":" SB_TEST_STRINGIFY(__LINE__) \
            ": failed assertion: " #e "\n"); \
        return 0; \
    } \
} while (0)

#define SB_TEST_ASSERT_SUCCESS(e) SB_TEST_ASSERT((e) == SB_SUCCESS)
#define SB_TEST_ASSERT_ERROR(e, v) SB_TEST_ASSERT((e) == (v))

#define SB_TEST_ASSERT_EQUAL_2(v, e1, e2, s) \
    SB_TEST_ASSERT((memcmp(&(e1), &(e2), (s)) == 0) == (v))

#define SB_TEST_ASSERT_EQUAL_1(v, e1, e2, unused) \
    SB_TEST_ASSERT_EQUAL_2(v, e1, e2, sizeof(e2))

#define SB_TEST_ASSERT_EQUAL_n(v, e1, e2, e3, a, ...) \
    a(v, e1, e2, e3)

#define SB_TEST_ASSERT_EQUAL(...) \
    SB_TEST_ASSERT_EQUAL_n(1, __VA_ARGS__, SB_TEST_ASSERT_EQUAL_2, \
        SB_TEST_ASSERT_EQUAL_1, NOT_ENOUGH_ARGUMENTS)

#define SB_TEST_ASSERT_NOT_EQUAL(...) \
    SB_TEST_ASSERT_EQUAL_n(0, __VA_ARGS__, SB_TEST_ASSERT_EQUAL_2, \
        SB_TEST_ASSERT_EQUAL_1, NOT_ENOUGH_ARGUMENTS)

#define SB_TEST_IMPL

#define SB_DEFINE_TEST(name) \
    extern _Bool sb_test_ ## name(void)

#ifndef SB_TEST_LIST
#define SB_TEST_LIST "sb_test_list.h"
#endif

#include SB_TEST_LIST

#undef SB_TEST_IMPL
#undef SB_DEFINE_TEST

#endif

#endif
