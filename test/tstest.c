// Last Update:2018-07-16 20:37:41
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
                    printf("upgrade %d%%, msg:%s\r\n", progress, msg);
                    break;
                }
            default:
                break;
        }
    }

    return 0;
}

int test_upgrade(unsigned char*image, int imagelen)
{
    ImageHeader header;
    BoeErr* ret = NULL;
    memcpy((uint8_t*)&header, image, sizeof(ImageHeader));
    if((memcmp(header.vendor, "hpb", 3) == 0)
            && (imagelen - sizeof(header) == header.len))
    {
        uint8_t *p_data = image + sizeof(ImageHeader);
        uint32_t chk = checksum(p_data, header.len);
        if(chk != header.chk)
        {
            printf("chk not match.\n");
            return 1;
        }
        
        ret = doAXU_Transport(&header, p_data);
        if(ret != BOE_OK)
            return 1;
        ret = doAXU_UpgradeStart(header.chk);
        if(ret == BOE_OK)
            printf("upgrade success.\n");
        else
            printf("upgrade failed.\n");
    }
    else
    {
        return 1;
    }
    return ret == BOE_OK ? 0 : 1;
}

static uint8_t *FBuf = NULL;
static int FBufLen = 128*1024*1024;
int main(int argc, char *argv[])
{
    if(argc < 3)
    {
        printf("usage: %s ethname filename\n", argv[0]);
        return -1;
    }
    char *ethname = argv[1];
    char *filename = argv[2];
    int nret = 0, rret = 0;

    FBuf = (uint8_t*)malloc(FBufLen);
    memset(FBuf, 0x0, FBufLen);
    uint8_t *p_pos = FBuf;
    int flen = 0;

    BoeErr *ret = doAXU_Init(ethname, axu_msg_handle, NULL);
    if(ret != BOE_OK)
    {
        printf("doAXU_Init failed.\n");
        return -1;
    }
    FILE *fp = fopen(filename, "rb");
    if(fp == NULL)
        goto end;

    while(1)
    {
        nret = fread(p_pos, 1, 1024, fp);
        if(nret > 0)
        {
            p_pos += nret;
            flen += nret;
        }
        else if(nret < 0)
            goto end;
        else
            break;
    }

    nret = test_upgrade(FBuf, flen);
    fclose(fp);
    if(nret == 0)
    {
        printf("test success.\n");
        rret = 0;
    }
    else
    {
        printf("test failed.\n");
        rret = 1;
    }



end:
    doAXU_Release();
    return rret;
}
