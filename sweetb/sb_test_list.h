/*
 * sb_test_list.h: multiply-included list of Sweet B tests
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

#ifdef SB_TEST_IMPL

SB_DEFINE_TEST(sha256_1);
SB_DEFINE_TEST(sha256_2);
SB_DEFINE_TEST(sha256_3);
SB_DEFINE_TEST(hmac_sha256);
SB_DEFINE_TEST(hmac_drbg);

SB_DEFINE_TEST(fe);
SB_DEFINE_TEST(mont_mult);
SB_DEFINE_TEST(mod_expt_p);

SB_DEFINE_TEST(mont_point_mult);
SB_DEFINE_TEST(mont_public_key);
SB_DEFINE_TEST(mont_shared_secret);
SB_DEFINE_TEST(mont_not_on_curve);
SB_DEFINE_TEST(mont_invalid_points);
SB_DEFINE_TEST(mont_early_errors);

SB_DEFINE_TEST(sw_h);
SB_DEFINE_TEST(exceptions);
SB_DEFINE_TEST(sw_point_mult_add);
SB_DEFINE_TEST(sw_early_errors);
SB_DEFINE_TEST(valid_public);
SB_DEFINE_TEST(compute_public);
SB_DEFINE_TEST(shared_secret);
SB_DEFINE_TEST(shared_secret_cavp_1);
SB_DEFINE_TEST(sign_rfc6979);
SB_DEFINE_TEST(sign_catastrophe);
SB_DEFINE_TEST(verify);
SB_DEFINE_TEST(verify_invalid);
SB_DEFINE_TEST(sign_k256);
SB_DEFINE_TEST(shared_secret_k256);

// Long tests near the end
SB_DEFINE_TEST(mont_iter);

SB_DEFINE_TEST(sw_point_mult_add_rand);
SB_DEFINE_TEST(sign_iter);
SB_DEFINE_TEST(sign_iter_k256);
SB_DEFINE_TEST(shared_iter);
SB_DEFINE_TEST(shared_iter_k256);

// NIST CAVP tests
SB_DEFINE_TEST(nist_ecdh_shared_secret_p256);
SB_DEFINE_TEST(nist_signatures_p256_sha1);
SB_DEFINE_TEST(nist_signatures_p256_sha224);
SB_DEFINE_TEST(nist_signatures_p256_sha256);
SB_DEFINE_TEST(nist_signatures_p256_sha384);
SB_DEFINE_TEST(nist_signatures_p256_sha512);
SB_DEFINE_TEST(nist_hmac_sha256);
SB_DEFINE_TEST(nist_sha256_small);
SB_DEFINE_TEST(nist_sha256_long);
SB_DEFINE_TEST(nist_sha256_monte);
SB_DEFINE_TEST(nist_hmac_drbg_sha256);

#endif
