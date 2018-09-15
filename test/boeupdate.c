// Last Update:2018-08-24 20:03:19
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
#include "boe_full.h"

typedef struct Tversion {
    unsigned char H;
    unsigned char M;
    unsigned char F;
    unsigned char D;
}TVersion;

typedef struct ImageHeader{
    uint8_t usage;
    uint8_t vendor[3];
    uint32_t chk;
    uint32_t len;
    TVersion version;
}ImageHeader;

#define MajorHver(vh)  (vh&0x0f)

int upgrade_callback(int progress, char *msg)
{
    static int lp = 0;
    
    if(progress >= 0 && progress <= 100)
    {
        if(lp != progress)
        {
            printf("Upgrade %d%%, msg:%s\r\n", progress, msg);
        }
        lp = progress;
    }
    return 0;
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
    BoeErr *ret = boe_test_init(ethname);
    if(ret != BOE_OK)
    {
        fprintf(stderr, "boe init failed.\n");
        return 1;
    }
    int nret = 0, rret = 0;
    unsigned char vh,vm,vf,vd;
    ret = boe_get_version(&vh, &vm, &vf, &vd);
    if(ret != BOE_OK)
    {
        fprintf(stderr, "get version failed.\n");
        return 1;
    }
    printf("Version on board is %d.%d.%d.%d\n", MajorHver(vh), vm, vf, vd);

    FBuf = (uint8_t*)malloc(FBufLen);
    memset(FBuf, 0x0, FBufLen);
    uint8_t *p_pos = FBuf;
    int flen = 0;

    FILE *fp = fopen(filename, "rb");
    if(fp == NULL)
    {
        fprintf(stderr, "fopen(%s) failed\n", filename);
        goto end;
    }


    while(1)
    {
        nret = fread(p_pos, 1, 1024, fp);
        if(nret > 0)
        {
            p_pos += nret;
            flen += nret;
        }
        else if(nret < 0)
        {
            goto end;
        }
        else
            break;
    }
    fclose(fp);
    ImageHeader *pheader = (ImageHeader*)FBuf;
    if(pheader->version.H == vh &&
            pheader->version.M == vm &&
            pheader->version.F == vf &&
            pheader->version.D == vd)
    {
        printf("version is same, don't upgrade.\n");
        return 0;
    }

    boe_reg_update_callback(upgrade_callback);

    ret = boe_upgrade(FBuf, flen);
    if(ret == BOE_OK)
    {
        printf("update success.\n");
        rret = 0;
    }
    else
    {
        printf("update failed.\n");
        rret = 1;
    }


end:
    boe_release();
    return rret;
}
