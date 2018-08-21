// Last Update:2018-08-21 10:37:38
/**
 * @file bwriteinfo.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-08-14
 */

#include "boe_full.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>

static void shex_dump_ln(unsigned char *buf, int len)
{
    for(int i =0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");

}

static void mac_to_array(char *mac, unsigned char *addr)
{
    sscanf(mac,"%2x-%2x-%2x-%2x-%2x-%2x",addr,addr+1, addr+2,addr+3,addr+4,addr+5);
}
static void array_to_mac(char *mac, unsigned char *addr)
{
    sprintf(mac, "%02X-%02X-%02X-%02X-%02X-%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

int main(int argc, char *argv[])
{
    unsigned char *mac, *account, *sn;

    unsigned char lmac[6];
    unsigned char rsn[21], rmac[6], raccount[43];
    unsigned char cid[64];
    memset(rsn, 0x0, sizeof(rsn));
    memset(rmac, 0x0, sizeof(rmac));
    memset(raccount, 0x0, sizeof(raccount));

    if(argc < 4)
    {
        printf("Usage: %s sn mac account\n", argv[0]);
        return 1;
    }

    sn = argv[1];
    mac = argv[2];
    account = argv[3];

    mac_to_array(mac, lmac);

    if(strlen(account) != 42)
    {
        printf("account(%s) format error, shoule be 0x....\n",account);
        return 1;
    }

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

    ret = boe_set_boesn(sn);
    if(ret != BOE_OK)
    {
        printf("set boesn failed.\r\n");
        return 1;
    }

    ret = boe_set_mac(lmac);
    if(ret != BOE_OK)
    {
        printf("set mac failed.\r\n");
        return 1;
    }

    ret = boe_set_bind_account(account);
    if(ret != BOE_OK)
    {
        printf("set account failed.\r\n");
        return 1;
    }

    ret = boe_get_boesn(rsn);
    if(ret != BOE_OK)
    {
        printf("get boesn failed.\r\n");
        return 1;
    }

    ret = boe_genkey(cid);
    if(ret != BOE_OK)
    {
        printf("genkey failed.\r\n");
        return 1;
    }
    ret = boe_lock_pk();
    if(ret != BOE_OK)
    {
        printf("lock pk failed.\r\n");
        return 1;
    }
    
    ret = boe_get_mac(rmac);
    if(ret != BOE_OK)
    {
        printf("get boesn failed.\r\n");
        return 1;
    }

    ret = boe_get_bind_account(raccount);
    if(ret != BOE_OK)
    {
        printf("get boesn failed.\r\n");
        return 1;
    }

    char rsmac[100];
    memset(rsmac, 0x0, sizeof(rsmac));
    array_to_mac(rsmac, rmac);
    if(strncmp(sn, rsn, strlen(sn)) != 0)
    {
        printf("sn set and get not match.\n");
        return 1;
    }
    if(strncmp(mac, rsmac, strlen(mac)) != 0)
    {
        printf("mac set and get not match.\n");
        return 1;
    }
    if(strncmp(account, raccount, strlen(account)) != 0)
    {
        printf("account set and get not match.\n");
        return 1;
    }
    char scid[129];
    memset(scid, 0, sizeof(scid));
    for(int i = 0; i < sizeof(cid); i++)
    {
        sprintf(scid+2*i, "%02x", cid[i]);
    }

    printf("%s\t%s\t%s\t%s",rsn, rsmac, raccount, scid);
    
    boe_release();

    return 0;
}

