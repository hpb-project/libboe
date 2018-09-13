// Last Update:2018-09-03 15:38:59
/**
 * @file update_record_info.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-09-03
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "boe_full.h"
#include "genid.h"

int main(int argc, char *argv[])
{
    unsigned char cid[64];
    char *account = NULL;
    if(argc < 2)
    {
        fprintf(stderr, "Usage: %s account\n", argv[0]);
        return 1;
    }
    account = argv[1];

    BoeErr *ret = boe_init();
    if(ret != BOE_OK)
    {
        printf("init failed.\r\n");
        return 1;
    }
    ret = boe_hw_check();
    if(ret != BOE_OK)
    {
        printf("hw check failed.\r\n");
        return 1;
    }

    if(!(account[0]=='0' && (account[1]=='x' || account[1]=='X')) || strlen(account) != 42)
    {
        fprintf(stderr, "account(%s) format error, shoule be 0x....\n",account);
        return 1;
    }

    ret = boe_set_bind_account(account);
    if(ret != BOE_OK)
    {
        fprintf(stderr, "set account failed.\r\n");
        return 1;
    }
    ret = boe_get_pubkey(cid);
    if(ret != BOE_OK)
    {
        ret = boe_genkey(cid);
        if(ret != BOE_OK)
        {
            fprintf(stderr, "get pubkey and genkey failed..\r\n");
            return 1;
        }
        else
        {
            ret = boe_lock_pk();
            if(ret != BOE_OK)
            {
                fprintf(stderr, "lock pk failed.\r\n");
            }
        }
    }

    char scid[129];
    memset(scid, 0, sizeof(scid));
    for(int i = 0; i < sizeof(cid); i++)
    {
        sprintf(scid+2*i, "%02x", cid[i]);
    }

    char shid[65];
    unsigned char p_buf[32];
    memset(p_buf, 0, sizeof(p_buf));
    memset(shid, 0, sizeof(shid));
    if(0 == general_id(p_buf))
    {
        for(int i = 0; i < sizeof(p_buf); i++)
        {
            sprintf(shid+2*i, "%02x", p_buf[i]);
        }
    }

    boe_release();
    printf("account:%s\n", account);
    printf("hid    :%s\n", shid);
    printf("cid    :%s\n", scid);
    return 0;
}

