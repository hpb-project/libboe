// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.


#ifndef TSU_CONNECTOR_H
#define TSU_CONNECTOR_H

#include "common.h"
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
#define FUNCTION_GEN_HASH 0x7

T_Package* tsu_package_new(uint8_t fid, uint32_t len);
int tsu_set_data(T_Package* p, uint16_t offset, uint8_t* data, uint32_t len);
void tsu_finish_package(T_Package *p);
int tsu_package_len(T_Package *p);

#endif  /*TSU_CONNECTOR_H*/
