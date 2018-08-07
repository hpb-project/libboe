// Last Update:2018-08-06 13:26:14
/**
 * @file sb_api.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-08-06
 */

#ifndef SB_API_H
#define SB_API_H
#include <stdint.h>

int p256_verify(unsigned char hash[32], unsigned char pubkey[64], unsigned char signature[64]);
#endif  /*SB_API_H*/
