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
    uint8_t     function_id;        // functin id.
    uint8_t     version;            // protocol versoin.
    uint8_t     status;             // error code return from fpga.
    uint8_t     sub_function;       // sub_function
    uint8_t     payload[];          // payload data pointor.
}T_Package;

typedef struct T_SLICE_PACKAGE {
    uint16_t task_id;
    uint16_t fragment_id;
    uint16_t fragment_cnt;
    uint16_t checksum;
    uint16_t payload_len;
    uint8_t  payload[];
}T_Slice;

#define FUNCTION_GEN_HASH 0x1
#define FUNCTION_ECSDA_CHECK 0x2 
#define FUNCTION_GEN_NEW_HASH 0x3
#define FUNCTION_ZSC_VERIFY 0x4

#define SUB_FUNC_NEW_HASH   (0x0)
#define SUB_FUNC_CHECK_HASH (0x1)

#define TSU_HASH_CHECK_LEN (64)

T_Package* tsu_package_new(uint8_t fid, uint32_t len, uint8_t hash_flag);
int tsu_set_data(T_Package* p, uint16_t offset, uint8_t* data, uint32_t len);
void tsu_finish_package(T_Package *p);

#endif  /*TSU_CONNECTOR_H*/
