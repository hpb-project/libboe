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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tsu_connector.h"
#include "common.h"
#include "atomic.h"
#define TRACE() printf("func:%s,line:%d\n", __FUNCTION__, __LINE__)

static uint32_t  g_sequence = 0;
static const TVersion g_tsu_version = 0x10;

#define fetch_tsu_package_sequence() atomic_fetch_and_add(&g_sequence,1)
#define TSU_PAYLOAD_MAX_SIZE (65535 - sizeof(T_Package))

T_Package* tsu_package_new(uint8_t fid, uint32_t len)
{
    if(len > TSU_PAYLOAD_MAX_SIZE)
        return NULL;
    T_Package *p = (T_Package*)malloc(sizeof(T_Package)+len);
    if(p)
    {
        p->sequence = fetch_tsu_package_sequence();
        p->version = g_tsu_version;
        p->is_response = 0;
        p->fragment_flag = 0;
        p->length = len;
        p->function_id = fid;
    }
    return p;
}

int tsu_set_data(T_Package* p, uint16_t offset, uint8_t* data, uint32_t len)
{
    if((offset + len) > p->length)
        return 1;
    memcpy(p->payload+offset, data, len);
    return 0;
}
void tsu_finish_package(T_Package *p)
{
    p->checksum = checksum(p->payload, p->length);
}

int tsu_package_len(T_Package *p)
{
    return sizeof(T_Package) + p->length;
}
