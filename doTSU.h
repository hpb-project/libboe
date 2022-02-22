// Last Update:2019-03-12 19:41:28
/**
 * @file doTSU.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-21
 */

#ifndef DO_T_S_U_H
#define DO_T_S_U_H
#include <stdint.h>
#include "boe.h"
#include "tsu_connector.h"

#define RP_CHKSUM_ERROR (0x13)
#define RANDOM_TIME_LIMIT (0x12)

typedef void (*TSU_PreSendCallback)(T_Package *package); // for test.

BoeErr* doTSU_Init(char *ethname, MsgHandle msghandle, void*userdata);
BoeErr* doTSU_Release();
BoeErr* doTSU_RecoverPub(uint8_t *sig, uint8_t *result);
BoeErr* doTSU_GetHash(uint8_t *hash, uint8_t *next_hash);
BoeErr* doTSU_GetNewHash(uint8_t *hash, uint8_t *next_hash);
BoeErr* doTSU_CheckHash(uint8_t *pre_hash, uint8_t *hash);
BoeErr* doTSU_RecoverPub_Async(uint8_t *sig, unsigned char *param, int param_len);
BoeErr* doTSU_ZSCVerify(uint8_t *data, int len);
BoeErr* doTSU_ZSCVerify_out_of_order(uint8_t *data, int len);
BoeErr* doTSU_ZSCVerify_Merge(uint8_t *data_1, int len_1, BoeErr **result_1, uint8_t *data_2, int len_2, BoeErr **result_2);

void doTSU_RegisAsyncCallback(AsyncCallback afun, void *data);
void doTSU_RegisPresendCallback(TSU_PreSendCallback pfun);

#endif  /*DO_T_S_U_H*/
