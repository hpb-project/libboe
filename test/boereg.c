// Last Update:2018-08-16 22:58:41
/**
 * @file boetest.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-08-08
 */
#include "boe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>

void usage(char *argv[])
{
    printf("Usage: %s 0 reg         -- read regiter\n", argv[0]);
    printf("       %s 1 reg val     -- write regiter\n", argv[0]);
}

int main(int argc, char *argv[])
{
    BoeErr *ret = boe_init();
    if(ret != BOE_OK)
    {
        printf("init failed.\r\n");
        return 1;
    }

    
    boe_release();

    return 0;
}

