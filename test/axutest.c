// Last Update:2018-07-14 11:29:59
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
#include "boe.h"


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

int test_get_random()
{
    uint32_t val;
    BoeErr *ret = NULL;
    ret = doAXU_GetRandom(&val);
    if(ret == BOE_OK)
    {
        printf("Random = %d\n", val);
        return 0;
    }
    return 1;
}
int test_get_boeid()
{
    uint32_t val;
    BoeErr *ret = NULL;
    ret = doAXU_GetBOEID(&val);
    if(ret == BOE_OK)
    {
        printf("get boe 0x%x.\n", val);
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
int test_set_boeid()
{
    uint32_t id = 0x1234abcd;
    BoeErr *ret = NULL;
    ret = doAXU_SetBoeID(id);
    printf("set boe 0x%x.\n", id);
    if(ret == BOE_OK)
    {
        return 0;
    }
    return 1;
}
int test_set_account()
{
    uint8_t account[32];
    for(int i = 0; i < 32; i++)
    {
        account[i] = i+0xa;
        printf("a[%d] = 0x%02x\n", i, account[i]);
    }
    BoeErr *ret = NULL;
    ret = doAXU_BindAccount(account);
    if(ret == BOE_OK)
    {
        return 0;
    }
    return 1;
}
int test_get_account()
{
    uint8_t account[32];

    BoeErr *ret = NULL;
    ret = doAXU_GetBindAccount(account);
    if(ret == BOE_OK)
    {
        for(int i = 0; i < 32; i++)
        {
            printf("a[%d]=0x%02x\n", i, account[i]);
        }
        return 0;
    }
    return 1;
}

static void hwsign(uint8_t *src, int srclen, uint8_t *sign, int slen)
{
    int len = srclen > slen ? slen : srclen;
    memset(sign, 0x0, slen);
    for(int i = 0; i < len; i++)
    {
        sign[i] = src[i]<<2;
    }
    return;
}

int test_get_hwsign()
{
    uint8_t account[32];
    int i = 0;
    for(i=0; i < 32; i++)
    {
        account[i] = i + 0xa;
    }
    uint8_t rsign[65], lsign[65];
    hwsign(account, sizeof(account), lsign, sizeof(lsign));

    BoeErr *ret = NULL;
    ret = doAXU_HWSign(account, sizeof(account), rsign);
    if(ret == BOE_OK)
    {
        for(i = 0; i < 65; i++)
        {
            if(rsign[i] != lsign[i])
            {
                printf("hwsign not equal.\r\n");
                return 1;
            }
        }
        return 0;
    }
    return 1;
}

int test_reset()
{
    BoeErr *ret = NULL;
    ret = doAXU_Reset();
    if(ret == BOE_OK)
    {
        return 0;
    }
    return 1;
}

void printf_help()
{
    printf("Cmd         Function        \n");
    printf(" 0           test_get_random\n");
    printf(" 1           test_get_boeid\n");
    printf(" 2           test_get_hw_ver\n");
    printf(" 3           test_get_fw_ver\n");
    printf(" 4           test_get_axu_ver\n");
    printf(" 5           test_set_boeid\n");
    printf(" 6           test_set_account\n");
    printf(" 7           test_get_account\n");
    printf(" 8           test_get_hwsign\n");
    printf(" 9           test_reset\n");
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
                    pfunc = test_get_boeid;
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
                    pfunc = test_set_boeid;
                    break;
                case 6:
                    pfunc = test_set_account;
                    break;
                case 7:
                    pfunc = test_get_account;
                    break;
                case 8:
                    pfunc = test_get_hwsign;
                    break;
                case 9:
                    pfunc = test_reset;
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
