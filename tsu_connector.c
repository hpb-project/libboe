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
#include "rs.h"

#define MAX_TSU_PACKAGE_PAYLOAD_LEN ((RS_MAX_PACKAGE_LEN) - sizeof(T_Package))
#define MAX_TSU_SLICE_PACKAGE_PAYLOAD_LEN (1024)

// #if (MAX_TSU_SLICE_PACKAGE_PAYLOAD_LEN) > ((MAX_TSU_PACKAGE_PAYLOAD_LEN) - sizeof(T_Slice))
// #error "slice payload length can't greater than tsu package payload length"
// #endif
#define TRACE() printf("func:%s,line:%d\n", __FUNCTION__, __LINE__)

static uint32_t  g_sequence = 0;
static uint8_t  g_task_id = 0;
static uint8_t  g_pid = 0;
static const unsigned char g_tsu_version = 0x10;

#define fetch_tsu_package_sequence() atomic_fetch_and_add(&g_sequence,1)

int tsu_set_pid(pid_t pid) 
{
    g_pid = (uint8_t)pid;
}


#define fetch_tsu_multi_package_task() atomic_fetch_and_add(&g_task_id,1)

T_Package* tsu_package_new(uint8_t fid, uint32_t len, uint8_t hash_flag)
{
    T_Package *p = (T_Package*)malloc(sizeof(T_Package)+len);
    if(p)
    {
        uint32_t seq = fetch_tsu_package_sequence();

        p->sequence = seq | g_pid << 24;
        p->version = g_tsu_version;
        p->status= 0;
        p->function_id = fid;
        if(1 == hash_flag)
        {
            p->sub_function = SUB_FUNC_CHECK_HASH;//check hash
        }
        else
        {
            p->sub_function = SUB_FUNC_NEW_HASH;//get hash
        }
        printf("tsu make package pid = %d, packageid = %u\n", g_pid, p->sequence);
    }
    return p;
}

int tsu_set_data(T_Package* p, uint16_t offset, uint8_t* data, uint32_t len)
{
    memcpy(p->payload+offset, data, len);
    return 0;
}

void tsu_finish_package(T_Package *p)
{
}

T_Slice* new_t_slice(uint8_t taskid, uint8_t checksum, uint8_t mode, uint8_t fragmentid, uint8_t *data, uint16_t payloadlen)
{
    T_Slice *s = (T_Slice*)malloc(sizeof(T_Slice) + payloadlen);
    if(NULL == s) 
    {
        return NULL;
    }
    memset(s, 0x0, sizeof(T_Slice) + payloadlen);
    s->task_id = taskid;
    s->checksum = checksum;
    s->proof_mode = mode;
    s->fragment_id = fragmentid;
    memcpy(s->payload, data, payloadlen);
    printf("new slice with taskid = 0x%02x, checksum = 0x%02x, mode = %d, fragment_id = %d, payload_len = 0x%02x\n",
        taskid, s->checksum, s->proof_mode, s->fragment_id, payloadlen);

    return s;
}

T_Multi_Package_List* tsu_zsc_proof_package_new(uint8_t fid, uint8_t mode, uint8_t* data, uint32_t length)
{
    T_Multi_Package_List *head = NULL, *p = NULL;
    T_Multi_Package_Node *node = NULL;
    T_Slice *slice = NULL;
    T_Package *package = NULL;
    int per_package_len = MAX_TSU_SLICE_PACKAGE_PAYLOAD_LEN;
    int cnt = length/per_package_len + (((length%per_package_len) > 0) ? 1 : 0);
    int i = 0, offset = 0, payloadlen = 0, slice_len = 0;

    if((MAX_TSU_SLICE_PACKAGE_PAYLOAD_LEN) > ((MAX_TSU_PACKAGE_PAYLOAD_LEN) - sizeof(T_Slice)))
    {
        printf("assert: tsu slice package ");
        abort();
    }
    //printf("tsu make max_package data length = %d, per_packet_len = %d\n", length, per_package_len);

    head = (T_Multi_Package_List*)malloc(sizeof(T_Multi_Package_List));
    if(NULL == head)
    {
        return NULL;
    }
    p = head;

    uint8_t task_id = fetch_tsu_multi_package_task();
    uint8_t checksum = checksum_byte(data,length);
    
    for(i=0; i < cnt; i++) 
    {
        printf("make slice for idx=%d, cnt = %d\n",i, cnt);
        payloadlen = (length-offset) > per_package_len ? per_package_len : (length-offset);
        slice = new_t_slice(task_id, checksum, mode, i, data+offset, payloadlen);
        if(NULL == slice)
        {
            return NULL;
        }
        slice_len = sizeof(T_Slice) + payloadlen;
        offset += payloadlen;
        package = tsu_package_new(fid, slice_len, 0);

        if(NULL == package)
        {
            return NULL;
        }

        tsu_set_data(package, 0, (uint8_t*)slice, slice_len);
        tsu_finish_package(package);

        // release slice
        free(slice);

        node = (T_Multi_Package_Node*)malloc(sizeof(T_Multi_Package_Node));
        if(NULL == node)
        {
            return NULL;
        }

        node->package = package;
        node->package_len = sizeof(T_Package) + slice_len;
        node->next = NULL;

        p->next = node;
        p = p->next;
    }
    return head;
}

void tsu_zsc_proof_package_release(T_Multi_Package_List* head)
{
    T_Multi_Package_Node *node;
    if(NULL != head)
    {
        while(NULL != head->next)
        {
            node = head->next;
            head->next = node->next;

            if(NULL != node->package)
            {
                free(node->package);
            }
            free(node);
        }
        free(head);
    }
}