// Last Update:2018-08-16 15:01:10
/**
 * @file boetest.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-08-08
 */
#include "boe_full.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>
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
        printf("board connect error.\r\n");
        return 1;
    }
    else
    {
        printf("board connect ok.\r\n");
    }
    boe_release();

    return 0;
}

