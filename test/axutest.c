// Last Update:2018-08-08 10:43:57
/**
 * @file axutest.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-07-13
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "doAXU.h"
#include "boe_full.h"


typedef int (*TestFunc)(void);
#define GetProgress(p)   (p->data[0])
#define GetProgressMsg(p) (p->data+1)
static int axu_msg_handle(uint8_t *data, int len, void *userdata)
{
    A_Package *p = (A_Package*)data;
    if(p->header.magic_aacc == AXU_MAGIC_START &&
            p->header.magic_ccaa == AXU_MAGIC_END)
    {
        switch(p->header.acmd)
        {
            case ACMD_BP_RES_UPGRADE_PROGRESS:
                {
                    int progress = GetProgress(p);
                    char *msg    = (char*)GetProgressMsg(p);
                    break;
                }
            default:
                break;
        }
    }

    return 0;
}
void hex_dump_ln(unsigned char *buf, int len)
{
    for(int i = 0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

int test_get_random()
{
    unsigned char r[32];
    BoeErr *ret = NULL;
    ret = doAXU_GetRandom(r);
    if(ret == BOE_OK)
    {
        printf("get random:");
        hex_dump_ln(r, sizeof(r));
        return 0;
    }
    return 1;
}
int test_get_boesn()
{
    unsigned char sn[21] = {0};
    BoeErr *ret = NULL;
    ret = doAXU_GetBOESN(sn);
    if(ret == BOE_OK)
    {
        printf("get sn:%s\n", sn);
        return 0;
    }
    return 1;
}
int test_get_hw_ver()
{
    TVersion ver;
    BoeErr *ret = NULL;
    ret = doAXU_GetHWVer(&ver);
    if(ret == BOE_OK)
    {
        printf("HW = 0x%02x\n", ver);
        return 0;
    }
    return 1;
}
int test_get_fw_ver()
{
    TVersion ver;
    BoeErr *ret = NULL;
    ret = doAXU_GetFWVer(&ver);
    if(ret == BOE_OK)
    {
        printf("FW = 0x%02x\n", ver);
        return 0;
    }
    return 1;
}
int test_get_axu_ver()
{
    TVersion ver;
    BoeErr *ret = NULL;
    ret = doAXU_GetAXUVer(&ver);
    if(ret == BOE_OK)
    {
        printf("FW = 0x%02x\n", ver);
        return 0;
    }
    return 1;
}
int test_set_boesn()
{
    uint32_t id = 0x1234abcd;
    unsigned char sn[21] = {0};
    memcpy(sn, "12345678901234567890", 20);
    BoeErr *ret = NULL;
    ret = doAXU_SetBoeSN(sn);
    printf("set boe sn:%s\n", sn);
    if(ret == BOE_OK)
    {
        return 0;
    }
    return 1;
}
// "0xb43557693992362c1cf2a4aba13edad2804160bf"
// "0x6703decbf077e9a2eaefa6f7ab57bcad83c28f19"
// "0xf978562dc272d4d47868d508354da19c21988258"
int test_set_account()
{
    char account[43] = {0};
    memcpy(account, "0xb43557693992362c1cf2a4aba13edad2804160bf", 42);

    BoeErr *ret = NULL;
    printf("set account :%s\n", account);
    ret = doAXU_BindAccount(account);
    if(ret == BOE_OK)
    {
        return 0;
    }
    return 1;
}
int test_get_account()
{
    char account[43] = {0};

    BoeErr *ret = NULL;
    ret = doAXU_GetBindAccount(account);
    if(ret == BOE_OK)
    {
        printf("get account :%s\n", account);
        return 0;
    }
    return 1;
}

int test_hw_sign()
{
    uint8_t data[32];
    int i = 0;
    for(i=0; i < sizeof(data); i++)
    {
        data[i] = i + 0xa;
    }
    uint8_t rsign[64];
    BoeErr *ret = NULL;
    ret = doAXU_HWSign(data, rsign);
    if(ret == BOE_OK)
    {
        printf("signature:");
        hex_dump_ln(rsign, sizeof(rsign));
        return 0;
    }
    return 1;
}

int test_genkey()
{
    unsigned char pubkey[64];
    BoeErr *ret = doAXU_Genkey(pubkey);
    if(ret == BOE_OK)
    {
        printf("genkey pubkey:");
        hex_dump_ln(pubkey, sizeof(pubkey));
        return 0;
    }
    return 1;
}

int test_get_pubkey()
{
    unsigned char pubkey[64];
    BoeErr *ret = doAXU_Get_Pubkey(pubkey);
    if(ret == BOE_OK)
    {
        printf("get pubkey:");
        hex_dump_ln(pubkey, sizeof(pubkey));
        return 0;
    }
    return 1;
}



int test_set_mac()
{
    unsigned char mac[6];
    mac[0] = 0xff;
    mac[1] = 0x12;
    mac[2] = 0x34;
    mac[3] = 0x45;
    mac[4] = 0x67;
    mac[5] = 0x89;
    BoeErr *ret = NULL;
    printf("set mac:");
    hex_dump_ln(mac, sizeof(mac));
    ret = doAXU_Set_MAC(mac);
    if(ret == BOE_OK)
    {
        return 0;
    }
    return 1;
}

int test_get_mac()
{
    unsigned char mac[6];
    BoeErr *ret = NULL;

    ret = doAXU_Get_MAC(mac);
    if(ret == BOE_OK)
    {
        printf("get mac:");
        hex_dump_ln(mac, sizeof(mac));
        return 0;
    }
    return 1;
}

void printf_help()
{
    printf("Cmd         Function        \n");
    printf(" 0            test_get_random\n");
    printf(" 1            test_get_boesn\n");
    printf(" 2            test_get_hw_ver\n");
    printf(" 3            test_get_fw_ver\n");
    printf(" 4            test_get_axu_ver\n");
    printf(" 5            test_set_boesn\n");
    printf(" 6            test_set_account\n");
    printf(" 7            test_get_account\n");
    printf(" 8            test_hw_sign\n");
    printf(" 9            test_genkey\n");
    printf(" 10           test_get_pubkey\n");
    printf(" 11           test_set_mac\n");
    printf(" 12           test_get_mac\n");
}


int main(int argc, char *argv[])
{
    if(argc < 2)
    {
        printf("usage: %s ethname \n", argv[0]);
        return -1;
    }
    char *ethname = argv[1];
    BoeErr *ret = doAXU_Init(ethname, axu_msg_handle, NULL);
    if(ret != BOE_OK)
    {
        printf("doAXU_Init failed.\n");
        return -1;
    }
    char input[20];
    while(1)
    {
        memset(input, 0, sizeof(input));
        printf("--->");
        fgets(input, sizeof(input), stdin);
        if(strncmp(input, "exit", 4) != 0)
        {
            if(strncmp(input, "help", 4) == 0)
            {
                printf_help();
                continue;
            }
            int cmd = atoi(input);
            TestFunc pfunc = NULL;
            switch(cmd)
            {
                case 0:
                    pfunc = test_get_random;
                    break;
                case 1:
                    pfunc = test_get_boesn;
                    break;
                case 2:
                    pfunc = test_get_hw_ver;
                    break;
                case 3:
                    pfunc = test_get_fw_ver; 
                    break;
                case 4:
                    pfunc = test_get_axu_ver;
                    break;
                case 5:
                    pfunc = test_set_boesn;
                    break;
                case 6:
                    pfunc = test_set_account;
                    break;
                case 7:
                    pfunc = test_get_account;
                    break;
                case 8:
                    pfunc = test_hw_sign;
                    break;
                case 9:
                    pfunc = test_genkey;
                    break;
                case 10:
                    pfunc = test_get_pubkey;
                    break;
                case 11:
                    pfunc = test_set_mac;
                    break;
                case 12:
                    pfunc = test_get_mac;
                    break;
                default:
                    printf("not support cmd %d.\n", cmd);
                    break;
            }
            if(pfunc != NULL)
            {
                if(pfunc() == 0)
                    printf("test success.\n");
                else
                    printf("test failed.\n");
            }
        }
        else
        {
            break;
        }
    }

    doAXU_Release();
    return 0;
}
