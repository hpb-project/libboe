/*
 * sb_test.c: test driver for Sweet B tests
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

#include <unistd.h>
#include <inttypes.h>
#include <string.h>

#ifdef SB_TEST

static int usage(const char* procname)
{
    printf("Usage: %s [-c count] [-t test]\n", procname);
    printf("\tIf -t is supplied, the test is run for count iterations.\n");
    printf("\tIf -c is not supplied, count defaults to "
               SB_TEST_STRINGIFY(SB_TEST_ITER_DEFAULT) "\n");
    return 1;
}

int main(const int argc, char** const argv)
{
    int option;
    uintmax_t test_iter = 8192;
    _Bool test_iter_supplied = 0;
    const char* test_iter_match = NULL;
    while ((option = getopt(argc, argv, "t:c:")) >= 0) {
        switch (option) {
            case 't': {
                test_iter_match = optarg;
                continue;
            }
            case 'c': {
                char* end;
                test_iter = strtoumax(optarg, &end, 10);
                if (*optarg == 0 || *end != 0) {
                    return usage(argv[0]);
                }
                test_iter_supplied = 1;
                continue;
            }
            default: {
                printf("%s: unknown option %c\n", argv[0], option);
                return usage(argv[0]);
            }
        }
    }

    if (optind != argc) {
        return usage(argv[0]);
    }

    if (test_iter_supplied && test_iter_match == NULL) {
        printf("%s: -t must be supplied if -c is supplied!\n", argv[0]);
        return usage(argv[0]);
    }

    uint32_t test_count = 0;
    uint32_t test_passed = 0;

    if (test_iter_match == NULL) {

#define SB_TEST_IMPL

#define SB_DEFINE_TEST(name) do { \
    printf("test " #name "... "); \
    fflush(NULL); \
    test_count++; \
    if (sb_test_ ## name()) { \
        printf("passed!\n"); \
        test_passed++; \
    } else { \
        printf("failed!\n"); \
    } \
} while (0)

        printf("Running tests:\n");
#include SB_TEST_LIST
#undef SB_DEFINE_TEST

        printf("%" PRIu32 "/%" PRIu32 " tests passed\n", test_passed,
               test_count);
        if (test_passed != test_count) {
            return 1;
        }
    } else {
        _Bool (* test_iter_fn)(void) = NULL;
#define SB_DEFINE_TEST(name) do { \
    if (strlen(test_iter_match) == strlen(SB_TEST_STRINGIFY(name)) && \
        strcmp(test_iter_match, SB_TEST_STRINGIFY(name)) == 0) { \
            test_iter_fn = sb_test_ ## name; \
    } \
} while (0)

#include SB_TEST_LIST

        if (test_iter_fn == NULL) {
            printf("%s: unknown test name %s\n", argv[0], test_iter_match);
            return usage(argv[0]);
        }

        printf("Running %s for %" PRIuMAX " iterations... ", test_iter_match,
               test_iter);
        fflush(NULL);

        for (uintmax_t i = 0; i < test_iter; i++) {
            if (test_iter_fn() != 1) {
                printf("failed!\n");
                return 1;
            }
        }
        printf("passed!\n");
    }
    return 0;
}

#endif
