// Last Update:2018-08-06 13:27:32
/**
 * @file nntest.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-08-05
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sb_api.h"
#include "sb_sw_context.h"
#include "sb_sw_lib.h"

int p256_verify(unsigned char hash[32], unsigned char pubkey[64], unsigned char signature[64])
{
    sb_sw_context_t ctx;
    sb_sw_public_t  spubkey;
    sb_sw_signature_t ssignature;
    sb_sw_message_digest_t message;

    memcpy(spubkey.bytes, pubkey, sizeof(pubkey));
    memcpy(ssignature.bytes, signature, sizeof(signature));
    memcpy(message.bytes, hash, sizeof(hash));

    sb_error_t ret = sb_sw_verify_signature(&ctx,
            (const sb_sw_signature_t*)&ssignature,
            (const sb_sw_public_t*)&spubkey,
            (const sb_sw_message_digest_t*)&message,
            NULL,
            SB_SW_CURVE_P256,
            SB_DATA_ENDIAN_BIG);

    return ret;

}
