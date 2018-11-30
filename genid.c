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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include "sha3.h"

#define BUFFER_LEN (8*1024)

typedef struct BoardInfo {
    char board_id[100];
}BoardInfo;

typedef struct MacInfo {
    char mac_list[20][20];
    int  mac_num;
}MacInfo;

static const char *virtual_mac[] = {
    "00:05:69", //vmware1
    "00:0c:29", //vmware2
    "00:50:56", //vmware3
    "00:1c:14", //vmware4
    "00:1c:42", //parallels1
    "00:03:ff", //microsoft virtual 
    "00:0f:4b", //virtual iron 4
    "00:16:3e", //red hat xen, oracle vm, xen source, novell xen
    "08:00:27",  //virtualbox
    NULL
};

static int is_virtual_mac(const char* mac)
{
    int i = 0;
    int isvirtual = 0;
    for (; virtual_mac[i]!=NULL; i++)
    {
        if(strncmp(mac, virtual_mac[i], 8) == 0)
        {
            isvirtual = 1;
            break;
        }
    }
    return isvirtual;
}

static int exec_shell(const char *cmd, char * buf, int buflen)
{
    FILE *fp = popen(cmd, "r");
    int cnt = 0, readn = 0;
    memset(buf, 0x0, buflen);
    if(fp == NULL)
    {
        printf("xxxxxxxxxxxxxxxx popen failed and fp is NULL, cmd = %s, errors:%s .\n", cmd, strerror(errno));
        return 1;
    }
    while(cnt < buflen)
    {
        readn = fread(buf+cnt, buflen-cnt, 1, fp);
        if(readn <= 0)
            break;
        else 
            cnt += readn;
    }
    pclose(fp);
    return 0;

}

static int scan_board(BoardInfo *board, char *cmd_buf, int buflen)
{
    memset(board, 0x0, sizeof(BoardInfo));
    /* board id */
    int ret = exec_shell("dmidecode -s system-serial-number", cmd_buf, buflen);
    if(ret == 0)
    {
        strcpy(board->board_id, cmd_buf);
        board->board_id[strlen(cmd_buf)-1] = '\0';
    }

    return ret;
}

static int scan_mac(MacInfo *macinfo, char *cmd_buf, int buflen)
{
    memset(macinfo, 0, sizeof(MacInfo));
    /* mac address */
    char tmp_buf[2048] = {0};
    char cmd[1024] = {0};
    char *str1 = NULL, *token = NULL, *saveptr1 = NULL;
    // get all mac addr
    if(0 != exec_shell("ls /sys/class/net/ -l | grep -v 'virtual' | grep -v 'total' | awk '{print $9}'", cmd_buf, buflen))
    {
        printf("Boe genid get mac list failed.\n");
        return 1;
    }
    strcpy(tmp_buf, cmd_buf);
    for (str1 = tmp_buf; ; str1 = NULL) 
    {
        token = strtok_r(str1, "\n", &saveptr1);
        if (token == NULL)
            break;
        sprintf(cmd, "ifconfig %s| grep -Eo '[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}:[0-9a-fA-F]{2,2}'", token);
        if(0 == exec_shell(cmd, cmd_buf, buflen))
        {
            cmd_buf[strlen(cmd_buf)-1] = '\0';
            // filter virtual mac.
            if(!is_virtual_mac(cmd_buf))
            {
                memcpy(macinfo->mac_list[macinfo->mac_num], cmd_buf, strlen(cmd_buf));
                macinfo->mac_num++;
            }
        }
        else
        {
            printf("Boe get mac addr failed.\n");
            return 1;
        }
    }
    if(macinfo->mac_num <= 0)
    {
        return 1;
    }

    return 0;
}

static int s_general_id(MacInfo *macinfo, BoardInfo *board, unsigned char *id)
{
    int datalen = 0;
    for(int i = 0; i < macinfo->mac_num; i++)
    {
        datalen += strlen(macinfo->mac_list[i]);
    }
    datalen += strlen(board->board_id);

    uint8_t *merge_data = (uint8_t*)malloc(datalen);
    memcpy(merge_data, board->board_id, strlen(board->board_id));

    for(int i = 0, offset = strlen(board->board_id); i < macinfo->mac_num; i++)
    {
        memcpy(merge_data+offset, macinfo->mac_list[i], strlen(macinfo->mac_list[i]));
        offset += strlen(macinfo->mac_list[i]);
    }

    uint8_t sha256[32] = {0};
    SHA3_256(sha256, merge_data, datalen);
    memcpy(id, sha256, 32);
    free(merge_data);

    return 0;
}

static unsigned char *g_id = NULL;
int general_id(unsigned char *genid)
{
    BoardInfo       board;
    MacInfo         mac;
    char cmd_buf[BUFFER_LEN];
    int ret = 0;
    if(g_id != NULL)
    {
        memcpy(genid, g_id, 32);
    }
    else
    {
        ret += scan_board(&board, cmd_buf, sizeof(cmd_buf));
        ret += scan_mac(&mac, cmd_buf, sizeof(cmd_buf));
        if(ret == 0)
        {
            ret = s_general_id(&mac, &board, genid);
            if(ret == 0)
            {
                g_id = (unsigned char *)malloc(32);
                memcpy(g_id, genid, 32);
            }
        }
    }

    return ret;
}
