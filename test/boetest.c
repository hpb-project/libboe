// Last Update:2018-08-08 11:48:58
/**
 * @file boetest.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-08-08
 */
#include "boe_full.h"
#include <stdio.h>


int main(int argc, char *argv[])
{
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
    }
    else
    {
        printf("hw check success.\r\n");
    }
    boe_release();

    return 0;
}

