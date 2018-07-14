#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include "axu_connector.h"


int s2i(char *s)
{
    int val = 0;
    char *p;
    if(s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        val = strtol(s, &p, 16);
    }
    else
    {
        val = atoi(s);
    }
    return val;
}
int filelen(char *filename)
{
    struct stat statbuf;  
    stat(filename,&statbuf);  
    int size=statbuf.st_size;  

    return size;
}

int fileRead(char *filename, uint8_t*p_buf)
{
    uint8_t *p_pos = p_buf;
    int nret = 0;
    FILE *fp = fopen(filename, "rb");

    if(fp == NULL)
    {
        return 1;
    }

    while(1)
    {
        nret = fread(p_pos, 1, 1024, fp);
        if(nret > 0)
        {
            p_pos += nret;
        }
        else if(nret < 0)
            return 1;
        else
            break;
    }
    fclose(fp);
    return 0;
}

int fillHeader(ImageHeader *h, TVersion hw, TVersion fw, TVersion axu, 
        uint8_t *p_data, int len)
{
    h->usage = BD_USE_UPGRADE_FW;
    h->vendor[0] = 'h';
    h->vendor[1] = 'p';
    h->vendor[2] = 'b';
    h->len = len;
    h->chk = checksum(p_data, len);
    h->hw = hw;
    h->fw = fw;
    h->axu = axu;
    return 0;
}

int fileWrite(char *filename, uint8_t *p_buf, int len)
{
    char oname[1024] = {0};
    int ret = 0;
    sprintf(oname, "u%s", filename);
    FILE *fp = fopen(oname, "wb+");
    if(fp == NULL)
    {
        printf("open output file %s failed.\n", oname);
        return 1;
    }
    while(len > 0)
    {
        int wlen = len > 1024 ? 1024 : len;
        ret = fwrite(p_buf, 1, wlen, fp);
        if(ret < 0)
        {
            return 1;
        }
        len -= wlen;
        p_buf += wlen;
    }
    fclose(fp);

    return 0;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    if(argc < 5)
    {
        printf("usage: %s iname hwver fwver axuver\n", argv[0]);
        return 1;
    }
    TVersion hw, fw, axu;
    char *iname = argv[1];
    hw = s2i(argv[2]);
    fw = s2i(argv[3]);
    axu = s2i(argv[4]);
    int len = filelen(iname);
    uint8_t *p_buf = (uint8_t*)malloc(len + sizeof(ImageHeader));
    if(p_buf == NULL)
    {
        printf("malloc failed.\n");
        return 1;
    }
    char *p_data = p_buf + sizeof(ImageHeader);
    ret = fileRead(iname, p_data);
    if(ret != 0)
    {
        printf("file read error.\n");
        return 1;
    }
    ret = fillHeader((ImageHeader*)p_buf, hw, fw, axu, p_data,len);
    if(ret != 0)
    {
        printf("fillheader error.\n");
        return 1;
    }
    ret = fileWrite(iname, p_buf, len + sizeof(ImageHeader));
    if(ret != 0)
    {
        printf("fileWrite error.\n");
        return 1;
    }
    printf("mkimage success.\n");

    return 0;
}
