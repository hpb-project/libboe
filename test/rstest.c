// Last Update:2018-07-12 11:51:54
/**
 * @file rstest.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-07-12
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "rs.h"
// 负载长度需要大于46, 否则以太网会将包补充到46字节长度.
static char *s1[] = {
    "1123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234234",
    "aabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdbcd",
    "vvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzvxyzxyzaaaammmmoooo",
    "plmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmkplmk"
};
int fillinput(char *input, int len)
{
    static int idx = 0;
    strcpy(input, s1[idx]);
    idx++;
    idx %= 4;
    return 0;
}

int dump_hex(char *input, int len)
{
	int i = 0;
    for(i = 0; i < len; i++)
    {
        printf("[%d]=0x%02x\n", i, input[i]);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    char *ethname;
    int type, ret;
    if(argc < 3)
    {
        printf("usage: %s ethname type\r\n", argv[0]);
        exit(-1);
    }
    ethname = argv[1];
    type = atoi(argv[2]);
    if(type == 0)
        type = 0xFF00;
    else if(type == 1)
        type = 0xFF01;
    else if(type == 2)
        type = 0xFF02;
    else 
        printf("unknown type(%d).\n", type);

    char input[1024];
    char rcv[1024];
    int rlen = sizeof(rcv), wlen = 0;
    RSContext rs;
    ret = RSCreate(ethname, type, &rs);
    int waitcount;
    int failed = 0, success = 0;
    int test_count = 100;
    while(test_count--){
        waitcount = 30;
        memset(input, 0x0, sizeof(input));
        memset(rcv, 0x0, sizeof(rcv));

        fillinput(input, sizeof(input));
        printf("send %d bytes.\r\n", (int)strlen(input));
        wlen = strlen(input);
        rlen = sizeof(rcv);
        if(RSWrite(&rs, input, wlen) < 0)
        {
            printf("RSWrite failed.\n");
            failed++;
            break;
        }
        while(waitcount--)
        {
            ret = RSSelect(&rs, 200);
            if(ret > 0)
            {
                break;
            }
        }
        if(ret > 0)
        {
            ret = RSRead(&rs, rcv, &rlen);
            if(ret < 0)
            {
                printf("RSRead failed.\n");
                failed++;
                break;
            }
            if(rlen != wlen || strcmp(input, rcv) != 0)
            {
                ret = -1;
                printf("compare failed, rlen = %d, wlen = %d.\n", rlen, wlen);
                dump_hex(input, strlen(input));
                dump_hex(rcv, rlen);
                failed++;
                break;
            }
            else
                success++;
        }
        else if(ret == 0)
        {
            printf("RSSelect timeout.\n");
            failed++;
            continue;
        }
        else if(ret < 0)
        {
            printf("RSSelect failed.\n");
            failed++;
            break;
        }

        sleep(1);
    };
    RSRelease(&rs);
    if(failed > 0)
    {
        printf("rs test failed.\n");
        return -1;
    }
    else
    {
        printf("rs test success.\n");
        return 0;
    }

    return ret;
}
