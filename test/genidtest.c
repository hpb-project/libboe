// Last Update:2018-11-09 14:28:06
/**
 * @file genidtest.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-11-09
 */
#include <stdio.h>
#include "genid.h"
#include <stdlib.h>
#include <sys/time.h>

static struct timeval gTs, gTe;

#define PROFILE_START() \
    gettimeofday(&gTs, NULL);\

#define PROFILE_END() \
    gettimeofday(&gTe, NULL);\
    printf("--PROFILE-- cost time %ldms.\n", (gTe.tv_sec*1000000 + gTe.tv_usec - gTs.tv_sec*1000000 - gTs.tv_usec)/1000);

int main(int argc, char *argv[])
{
    int i = 0, ret = 0;
    unsigned char genid[32];

    PROFILE_START();
    for(i = 0; i < 200; i++)
    {
        ret = general_id(genid);
        if(ret != 0)
            printf("general_id failed\n");
    }
    PROFILE_END();
    return 0;
}
