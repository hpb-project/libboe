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

BoeErr* doTSU_Init(char *ethname, MsgHandle msghandle, void*userdata);
BoeErr* doTSU_Release();
BoeErr* doTSU_RecoverPub(uint8_t *sig, uint8_t *result);
BoeErr* doTSU_GetHash(uint8_t *hash, uint8_t *next_hash);
BoeErr* doTSU_GetNewHash(uint8_t *hash, uint8_t *next_hash);
BoeErr* doTSU_CheckHash(uint8_t *pre_hash, uint8_t *hash);
BoeErr* doTSU_RecoverPub_Async(uint8_t *sig, unsigned char *param, int param_len);
void doTSU_RegisAsyncCallback(AsyncCallback afun, void *data);
#endif  /*DO_T_S_U_H*/
