// Last Update:2018-08-21 11:07:44
/**
 * @file bwriteinfo.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-08-14
 */

#include "boe.h"
#include "genid.h"
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
    unsigned int i_addr[6];
    sscanf(mac,"%2x-%2x-%2x-%2x-%2x-%2x",i_addr,i_addr+1, i_addr+2,i_addr+3,i_addr+4,i_addr+5);
    addr[0] = i_addr[0]&0xff;
    addr[1] = i_addr[1]&0xff;
    addr[2] = i_addr[2]&0xff;
    addr[3] = i_addr[3]&0xff;
    addr[4] = i_addr[4]&0xff;
    addr[5] = i_addr[5]&0xff;
}
static void array_to_mac(char *mac, unsigned char *addr)
{
    sprintf(mac, "%02X-%02X-%02X-%02X-%02X-%02X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

int main(int argc, char *argv[])
{
    unsigned char *mac, *account;
    int sn;

    unsigned char lsn[21], lmac[6], laccount[42];
    unsigned char rsn[21], rmac[6], raccount[43];
    const char *sn_pre = "10001012018080800";
    unsigned char cid[64];
    memset(rsn, 0x0, sizeof(rsn));
    memset(raccount, 0x0, sizeof(raccount));


    BoeErr *ret = boe_init();
    if(ret != BOE_OK)
    {
        printf("init failed.\r\n");
        return 1;
    }
    ret = boe_hw_check();
    if(ret != BOE_OK)
    {
        fprintf(stderr, "boe check failed.\n");
        return 1;
    }


    ret = boe_get_boesn(rsn);
    if(ret != BOE_OK)
    {
        printf("get boesn failed.\r\n");
        return 1;
    }

    ret = boe_get_pubkey(cid);
    if(ret != BOE_OK)
    {
        printf("genkey failed.\r\n");
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

    char scid[129];
    memset(scid, 0, sizeof(scid));
    for(int i = 0; i < sizeof(cid); i++)
    {
        sprintf(scid+2*i, "%02x", cid[i]);
    }

    printf("SN: %s\n", rsn);
    printf("MAC: %s\n", rsmac);
    printf("Account: %s\n", raccount);
    printf("CID: %s\n", scid);
    unsigned char genid[32];
    int nret = general_id(genid);
    if(nret == 0)
    {
	printf("HID: ");
	shex_dump_ln(genid, sizeof(genid));
    }
    
    boe_release();

    return 0;
}

