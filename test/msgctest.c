// Last Update:2018-07-12 22:05:03
/**
 * @file msgctest.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-07-12
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "rs.h"
#include "msgc.h"

typedef struct LBContext{
    RSContext  rs;
    MsgContext wqc;
}LBContext;

static LBContext glb;

static char *s1[] = {
    "1123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234234",
    "aabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdbcd",
    "vvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzxyzaaaammmmoooo",
    "plmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmk"
};
int fillinput(char *input)
{
    static int idx = 0;
    strcpy(input, s1[idx]);
    idx++;
    idx %= 4;
    return 0;
}

static int axu_check_response(uint8_t* data, int plen, uint32_t uid)
{
    return 1;
}
static int doCommand(uint8_t*p, int len, AQData **d)
{
    MsgContext *wqc = &glb.wqc;
    WMessage * wm = WMessageNew(0, axu_check_response, 100000, (uint8_t*)p, len);
    if(msgc_send(wqc, wm) == 0)
    {
        AQData *q = msgc_read(wqc, wm);
        if(q == NULL || q->buf == NULL)
            return -1;
        *d = q;
        return 0;
    }
    else
        return -1;
}
int dotest()
{
    char p[1024];
    AQData *r = NULL;
    int ret = 0;
    if(p)
    {
        fillinput(p);
        ret = doCommand(p, strlen(p), &r);
        if(ret == 0)
        {
            if((r->len == strlen(p)) && (memcmp(r->buf, p, strlen(p))==0))
            {
                ret = 0;
            }
            else
            {
                ret = -1;
            }
            aqd_free(r);
            return ret;
        }
        return ret;
    }
    else
    {
        return -1;
    }
}


int msgc_test(char *ethname, int type)
{
    int ret = 0;
    LBContext *ctx = &glb;
    ret = RSCreate(ethname, type, &(ctx->rs));
    if(ret != 0)
    {
        return -1;
    }
    ret = msgc_init(&ctx->wqc, &ctx->rs, NULL, NULL);
    if(ret != 0)
    {
        RSRelease(&ctx->rs);
        return -1;
    }
    for(int i = 0; i < 100; i++)
    {
        if(dotest() != 0)
        {
            printf("msgc test failed.\r\n");
            ret = 1;
            goto failed;
        }
        else
        {
            printf("send and recv success.\n");
        }

    }
    printf("msgc test success.\n");
    ret = 0;

failed:
    RSRelease(&ctx->rs);
    msgc_release(&ctx->wqc);
    return ret;
}


int main(int argc, char *argv[])
{
    if(argc < 3)
    {
        printf("usage: %s ethname type\n", argv[0]);
        return -1;
    }
    int type = atoi(argv[2]);
    if(type == 0)
        type = 0xff00;
    else if(type == 1)
        type = 0xff01;
    else if(type == 2)
        type = 0xff02;

    msgc_test(argv[1], type);
    return 0;
}
