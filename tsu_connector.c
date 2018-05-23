// Last Update:2018-05-23 16:48:40
/**
 * @file tsu_connector.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-05-23
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tsu_connector.h"
#include "community.h"
#include "common.h"
#include "atomic.h"

typedef struct T_PACKAGE{
    uint32_t    sequence;           // package sequence id.
    uint8_t     version;            // protocol version.
    uint8_t     is_response;        // the package is request(0) or responsed(1).
    uint8_t     fragment_flag;      // 0: no fragment; 1: first fragment; 
                                    // 2: middle fragment; 3:last fragment.
    uint8_t     function_id;        // task type.
    uint16_t    reserved;           // reserved.
    uint16_t    length;             // payload data length.
    uint32_t    checksum;           // payload data checksum.
    uint8_t     payload[];          // payload data pointor.
}T_Package;

#define FUNCTION_ECSDA_SIGN 0x1 
#define FUNCTION_ECSDA_CHECK 0x2 
#define FUNCTION_SHA3_256 0x3 
#define FUNCTION_SHA3_512 0x4 
#define FUNCTION_AES256 0x5 
#define FUNCTION_RLP 0x6
static uint32_t  g_sequence = 0;
static const uint8_t g_tsu_version = 0x10;

#define fetch_package_sequence() atomic_fetch_and_add(&g_sequence,1)
#define TSU_PAYLOAD_MAX_SIZE (65535)

void init_package(T_Package *pack)
{
    pack->sequence = fetch_package_sequence();
    pack->version = g_tsu_version;
    pack->is_response = 0;
    pack->fragment_flag = 0;
}


uint8_t get_hw_version(void)
{
    // Todo: read from register.
    return 0x10;

}
uint8_t get_fw_version(void)
{
    // Todo: read from arm.
    return 0x10;
}

uint32_t get_boeid(void)
{
    //Todo: read register.
    return 0;
}

int set_boeid(uint32_t boeid)
{
    // Todo: write register.
    return 0;
}

int validate_sign(u256 r, u256 s, uint8_t v, u256 x, u256 y)
{
    T_Package *pack = (T_Package*)malloc(sizeof(T_Package) + sizeof(u256) + sizeof(u256) + 1);
    if(pack == NULL)
        return -2;
    init_package(pack);
    pack->function_id = FUNCTION_ECSDA_CHECK;
    memcpy(pack->payload, r.data, sizeof(u256));
    pack->length = sizeof(u256);
    memcpy(pack->payload+sizeof(u256), s.data, sizeof(u256));
    pack->length += sizeof(u256);
    memcpy(pack->payload+2*sizeof(u256), &v, 1);
    pack->length += 1;
    pack->checksum = checksum(pack->payload, pack->length);

    // Todo: send request.
    if(pcie_write((uint8_t*)pack, pack->length + sizeof(T_Package)) < 0)
    {
        free(pack);
        return -3;
    }


    T_Package *res = (T_Package*)malloc(sizeof(T_Package) + 2*sizeof(u256));
    u256 res_x, res_y;
    // Todo: get response.
    if(pcie_read((uint8_t*)res, sizeof(T_Package) + 2*sizeof(u256)) < 0)
    {
        free(res);
        return -4;
    }
    memcpy(res_x.data, res->payload, sizeof(u256));
    memcpy(res_y.data, res->payload+sizeof(u256), sizeof(u256));

    free(res);

    if(memcmp(res_x.data, x.data, sizeof(u256))==0 &&
            memcmp(res_y.data, y.data, sizeof(u256)==0 ))
    {
        return 0; // success.
    }
    return 1; // validate_sign failed.
}

int get_randnum()
{
    //Todo: get random.
    return 0;
}

int hw_sign(uint8_t *info, int info_len, sign_result_t *result)
{
    if(info_len > TSU_PAYLOAD_MAX_SIZE)
        return -1;
    T_Package *pack = (T_Package*)malloc(sizeof(T_Package) + info_len);
    if(pack == NULL)
        return -2;
    init_package(pack);
    pack->function_id = FUNCTION_ECSDA_SIGN;
    memcpy(pack->payload, info, info_len);
    pack->length = info_len;
    pack->checksum = checksum(pack->payload, pack->length);

    // Todo: send request.
    if(pcie_write((uint8_t*)pack, info_len + sizeof(T_Package)) < 0)
    {
        free(pack);
        return -3;
    }

    // Todo: get response.
    T_Package *res = (T_Package*)malloc(sizeof(T_Package) + sizeof(sign_result_t));
    if(pcie_read((uint8_t*)res, sizeof(T_Package) + sizeof(sign_result_t)) < 0)
    {
        free(res);
        return -4;
    }
    memcpy(result->r.data, res->payload, sizeof(u256));
    memcpy(result->s.data, res->payload+sizeof(u256), sizeof(u256));
    memcpy(&(result->v), res->payload+2*sizeof(u256), 1);

    free(res);
    return 0;
}
