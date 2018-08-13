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
    uint8_t     function_id;            // protocol version.
    uint8_t     version;        // the package is request(0) or responsed(1).
    uint8_t     status;      // 0: no fragment; 1: first fragment; 
                                    // 2: middle fragment; 3:last fragment.
    uint16_t    reserved;           // reserved.
    uint8_t     payload[];          // payload data pointor.
}T_Package;

#define FUNCTION_GEN_HASH 0x1
#define FUNCTION_ECSDA_CHECK 0x2 


T_Package* tsu_package_new(uint8_t fid, uint32_t len);
int tsu_set_data(T_Package* p, uint16_t offset, uint8_t* data, uint32_t len);
void tsu_finish_package(T_Package *p);

#endif  /*TSU_CONNECTOR_H*/
