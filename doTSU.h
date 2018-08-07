// Last Update:2018-07-12 19:54:42
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
#include "boe_full.h"
#include "tsu_connector.h"

BoeErr* doTSU_Init(char *ethname, MsgHandle msghandle, void*userdata);
BoeErr* doTSU_Release();
BoeErr* doTSU_RecoverPub(uint8_t *sig, uint8_t *result);
BoeErr* doTSU_GetHash(uint8_t *hash, uint8_t *next_hash);
#endif  /*DO_T_S_U_H*/
