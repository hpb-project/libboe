// Last Update:2018-10-22 16:01:22
/**
 * @file boetest.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-08-08
 */
#include "boe_full.h"
#include "doTSU.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>

#define BUF_THR   20       //缓存门限
#define TEST_NUMB 10000   //测试次数

static struct timeval gTs, gTe;
static struct timezone gTz;

#define PROFILE_START() \
	gettimeofday(&gTs, &gTz);\

#define PROFILE_END() \
	gettimeofday(&gTe, &gTz);\
printf("--PROFILE-- cost time %ldms.\n", (gTe.tv_sec*1000000 + gTe.tv_usec - gTs.tv_sec*1000000 - gTs.tv_usec)/1000);

static void shex_dump_ln(unsigned char *buf, int len)
{
	int i = 0;
	for(i =0; i < len; i++)
	{
		printf("%02x", buf[i]);
	}
	printf("\n");

}

static int multipacket_test(void)
{
	unsigned char *data = (unsigned char *)malloc(1000*5);
	int i = 0, j = 0, idx = 0;
	for (i = 0; i < 5; i++)
	{
		for (j = 0; j < 1000; j++)
		{
			idx = 1000*i + j;
			data[idx] = i+1;
		}
	}

	BoeErr *ret = doTSU_ZSCVerify(data, 1000*5);
	if(ret != BOE_OK)
	{
		printf("zscverify failed.\n");
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		printf("Usage: %s ethname \n", argv[0]);
		return 1;
	}

	char *ethname = argv[1];
	BoeErr *ret = boe_inner_tsu_init(ethname);
	if(ret != BOE_OK)
	{
		printf("init failed.\r\n");
		return 1;
	}
	else
	{
		printf("init ok.\r\n");
	}
	{
		// hash test 
		if(0 == multipacket_test())
		{
			printf("multi packet test ok.\n");
		}
		else
		{
			printf("multi packet failed.\n");
			return 3;
		}
	}

	boe_release();

	return 0;
}

