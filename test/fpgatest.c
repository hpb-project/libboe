// Last Update:2020-10-13 11:03:20
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
#define TOTAL_NUMBER 10000   //测试次数

static struct timeval gTs, gTe;
static struct timezone gTz;

#define PROFILE_START() \
	gettimeofday(&gTs, &gTz);\

#define PROFILE_END() \
	gettimeofday(&gTe, &gTz);\
printf("--PROFILE-- cost time %ldms.\n", (gTe.tv_sec*1000000 + gTe.tv_usec - gTs.tv_sec*1000000 - gTs.tv_usec)/1000);

typedef struct rsv_t{
	uint8_t r[32];
	uint8_t s[32];
	uint8_t h[32];
	uint8_t v;
	uint32_t x[32];
	uint32_t y[32];
}rsv_t;

static rsv_t rsv_array[TOTAL_NUMBER+1];
static uint32_t gTotal = 0;
static uint32_t gErrcnt = 0;
static volatile int gCurrent = 0;
static volatile int gCount = 0;

static void shex_dump_ln(unsigned char *buf, int len)
{
	for(int i =0; i < len; i++)
	{
		printf("%02x", buf[i]);
	}
	printf("\n");

}

int get_data(rsv_t **data)
{
	int pidx = gCurrent++;
	gCount++;
	if((pidx >= TOTAL_NUMBER) || (pidx >= gTotal))
	{
		return -1;
	}
	*data = &rsv_array[pidx];
	return 0;
}

static int async_tsu_callback(int type, unsigned char * response, int res_len, unsigned char *param, int param_len, unsigned char * source, void * userdata)
{
	unsigned char *pub = response;
	unsigned char *sig = source;
	uint32_t pointer = (uint32_t)param;
	rsv_t* pdata = (rsv_t*)pointer;

	if (pub == NULL)
	{
		printf("recover pubkey got NULL\n");
	}
	else
	{
		if (pdata == NULL)
		{
			printf("got param error in async_tsu_callback.\n");
			return 0;
		}
		if(memcmp(pdata->x, pub, 32) == 0 &&
			memcmp(pdata->y, pub+32, 32) == 0)
		{
			if (gCount%5000 == 0)
			{
				printf("recover pubkey current = %d\n", gCount);
			}
		}
		else
		{
			printf("pubkey compare error.\n");
			shex_dump_ln(pub,64);
			exit(1);
		}
	}
    return 0;
}

void *test_ecc(void *usrdata)
{
	unsigned char sig[97];
	unsigned char pub[64];
	while(1)
	{
		memset(sig, 0, sizeof(sig));
		memset(pub, 0, sizeof(pub));
		rsv_t *pdata;
		if (0 == get_data(&pdata)) 
		{
			memcpy(sig+0, pdata->r, 32);
			memcpy(sig+32, pdata->s, 32);
			memcpy(sig+64, pdata->h, 32);
			sig[96] = pdata->v;

			if (0 != 0)
			{
				BoeErr *bret = doTSU_RecoverPub(sig, pub);
				if(bret == BOE_OK)
				{
					if(memcmp(pdata->x, pub, 32) == 0 &&
							memcmp(pdata->y, pub+32, 32) == 0)
					{
						if (gCount%5000 == 0)
						{
							printf("recover pubkey current = %d\n", gCount);
						}
						continue;
					}
					else
					{
						printf("pubkey compare error.\n");
						shex_dump_ln(pub,64);
						exit(1);
					}
				}
				else
				{
					printf("msg send/receive error.\n");
				}
			}
			else
			{
				uint32_t pointer = (uint32_t)pdata;
				BoeErr *bret = doTSU_RecoverPub_Async(sig, (unsigned char*)&pointer, sizeof(uint32_t));
				if(bret != BOE_OK)
				{
					printf("msg send/receive error.\n");
				}
			}
			gErrcnt++;
		}
		else
		{
			gCurrent = 0;
		}
	}
}



static void load_data(int argc, char *argv[])
{
	char *data_path1 = argv[2];
	char *data_path2 = argv[3];
	char *data_path3 = argv[4];
	FILE *fd1;
	FILE *fd2;
	FILE *fd3;
	uint8_t  r[32],s[32],h[32],v, x[32], y[32];
	if (((fd1 = fopen(data_path1, "r")) == NULL)||((fd2 = fopen(data_path2, "r")) == NULL)||((fd3 = fopen(data_path3, "r")) == NULL))
	{
		printf("open data file error!!\n");
		exit(1);
	}

	while((gTotal < TOTAL_NUMBER) && (!feof(fd1)) && (!feof(fd2))  && (!feof(fd3)))
	{
		rsv_t *p = &(rsv_array[gTotal]);
		//读取一组数据并发送
		for(int i=0;i<32;i++)
		{
			fscanf(fd1,"%hhu,%hhu,%hhu\n",&r[i],&s[i],&h[i]);
		}
		fscanf(fd2,"%hhu\n",&v);
		for(int i=0;i<32;i++)
		{
			fscanf(fd3,"%hhu,%hhu\n",&x[i],&y[i]);
		}

		memcpy(p->r, r, sizeof(r));
		memcpy(p->s, s, sizeof(s));
		memcpy(p->h, h, sizeof(h));
		memcpy(p->x, x, sizeof(x));
		memcpy(p->y, y, sizeof(y));
		p->v = v;
		gTotal++;
	}
	fclose(fd1);
	fclose(fd2);
	fclose(fd3);
}

#define KNOWN_HASH_COUNT 10 

static const char *hash_serial_v1 [KNOWN_HASH_COUNT] = {
	"7dcabd53a3b5fbd6cb014416ddee75d07dcabd53a3b5fbd6cb014416ddee75d0",
	"06ad07e25b57b7ec3fd5ee5a31f85ff37ad9c1b70cb3268e92b3df4b4c4a1313",
	"c030b0f85b26802e80c63c5084ba44a59c9bf3f231f71ee05a9fe8d65115e35a",
	"d42f7189e3fcf922de9438b178492abb5f16020edb3402185ef2ed6e630fec18",
	"62177a86a3ec7ef4e4cbd27fa0b7e032c9193ec5afef4215fa2e350c04ad8644",
	"56178305a7454a77893d5b1679e1cc15441ecdd7b21c015212e17e70566dd792",
	"5cbd2862d297cbb605527930d2c17deff2cade7054e0e8341ddba3fc854b558c",
	"3a44f859d1c269174d0192bf3ad2b18057a8c4904a8acf368bcb464ecc65bac1",
	"0e55b054ee1bee82ec27c0a6b8773f971503fa7c4c43dbe9d2ab51a9a6ebbd74",
	"fcbeb2721937f97739b23984fd011876db3cdc24b6e942013749b9e93e468fbc"
};

static const char *hash_serial_v2 [KNOWN_HASH_COUNT] = {
	"694d1160ec4a8842e5c14ca9d4a471425b6fbb441518698e09303ea79fda1917",
	"4582e2d6d337d2d46295c298422506d2a304a3f32387292e0925c3a9f81b8e0f",
	"4c1669c8565ed042475c8f41004ed0963dda7f4890482baf9e056ef01d77d688",
	"b77730c21f9bfcdf9791322c0351f9dc8f9481b2ac31e228806a7e1fd9712a57",
	"7928c34548841a863b796c2c1a73d00b8d8bdc22b2371fcb9891bb6ce803580d",
	"7cbbd5c29d89b5b98f0ae5dfbb2c307993e888d17181d48b3d0169df0fd4ceb1",
	"bf9295b9971146bee155247aa22f4832517a0a4f917f34f60de8e3016e805ab0",
	"d7e51f102e5c73da8388cee74dafe12274892cb24debbbe2ababcb375f1080b3",
	"496e268ea67dc9e33afb905750ddea6321259f52b6089718bc832d8a24d5202a",
	"97738b7fa96b28d2984857284421d3729f3ecf12a002fa38dc02e3e513bfeb0a"
};

static void hash_to_string(unsigned char *hash, char *str)
{
	for(int i = 0; i < 32; i++)
	{
		char byte[3] = {0};
		memset(byte, 0x0, sizeof(byte));
		sprintf(byte,"%02x",hash[i]);
		strcat(str,byte);
	}
}

#define HASH_TEST_COUNT 10000
void *hash_V2_test(void *usrdata)
{
	unsigned char shash[32];
	unsigned char last[32];
	char hash_str[65] = {0};
	unsigned char p_status = 0;
	unsigned char p_result = 0;
	
	memset(shash, 0x00, sizeof(shash));
	memset(last, 0x00, sizeof(last));

	for(int i = 0; i < HASH_TEST_COUNT; i++)
	{
	    BoeErr *ret = doTSU_GetNewHash(last, shash);
	    if(ret != BOE_OK)
	    {
	        if(BOE_HASH_TIME_LIMIT == ret)
	        {
	            printf("get hash time limite, sleep 0.5s continue \n");
	            usleep(500*1000);
	        }
			else 
			{
				printf("boe_get_n_random failed,error ecode = %d\n",ret->ecode);
			}

			i = i - 1;
			continue;
	    }

	    memset(hash_str, 0, sizeof(hash_str));
	    hash_to_string(shash, hash_str);
		if(i < KNOWN_HASH_COUNT) 
		{
			if(strcmp(hash_str, hash_serial_v2[i]) != 0)
			{
				printf("get random error, not matched with %s.\n", hash_serial_v2[i]);
				printf("last = ");
				shex_dump_ln(last, sizeof(last));
				printf("hash = ");
				shex_dump_ln(shash, sizeof(shash));
			}
		}

	    {
	        ret = doTSU_CheckHash(last, shash);
	        if(ret != BOE_OK)
	        {
	            printf("boe_check_random failed,error code = %d\n",ret->ecode);
	        }
			else 
			{
				printf("boe get random-v2 and check passed.\n");
			}
	    }
	    memcpy(last, shash, sizeof(shash));
	}
	return 0;
}

void *hash_V1_test(void *usrdata)
{
	unsigned char shash[32];
	unsigned char last[32];
	char hash_str[65] = {0};
	unsigned char p_status = 0;
	unsigned char p_result = 0;
	
	memset(shash, 0x00, sizeof(shash));
	memset(last, 0x00, sizeof(last));

	for(int i = 0; i < HASH_TEST_COUNT; i++)
	{
	    BoeErr *ret = doTSU_GetHash(last, shash);
	    if(ret != BOE_OK)
	    {
			printf("boe_get_s_random failed,error ecode = %d\n",ret->ecode);
			continue;
	    }

	    memset(hash_str, 0, sizeof(hash_str));
	    hash_to_string(shash, hash_str);
		if(i < KNOWN_HASH_COUNT) 
		{
			if(strcmp(hash_str, hash_serial_v1[i]) != 0)
			{
				printf("get random error, not matched with %s.\n", hash_serial_v1[i]);
				printf("last = ");
				shex_dump_ln(last, sizeof(last));
				printf("hash = ");
				shex_dump_ln(shash, sizeof(shash));
			}
		}
		sleep(1);
	    memcpy(last, shash, sizeof(shash));
	}
	return 0;
}

static int tsu_msg_handle(uint8_t *data, int len, void *userdata)
{
    return 0;
}


int main(int argc, char *argv[])
{
	if(argc < 5)
	{
		printf("Usage: %s ethname rsh rsv xy\n", argv[0]);
		return 1;
	}

	char *ethname = argv[1];
	BoeErr *ret = NULL;
	doTSU_RegisAsyncCallback(async_tsu_callback, (void *)NULL);
    ret = doTSU_Init(ethname, tsu_msg_handle, (void*)NULL);
    if(ret != BOE_OK)
    {
        return -1;
    }

	load_data(argc, argv);

	while (1)
	{
        int r = 0;
		pthread_t th1;
		pthread_t th2;
		pthread_t th3;
		pthread_t th4;
		pthread_t th5;

		r = pthread_create(&th1, NULL, test_ecc, NULL);
		r = pthread_create(&th4, NULL, test_ecc, NULL);
		r = pthread_create(&th5, NULL, test_ecc, NULL);
		r = pthread_create(&th2, NULL, hash_V2_test, NULL);
		r = pthread_create(&th3, NULL, hash_V1_test, NULL);

		pthread_join(th1, NULL);
		pthread_join(th4, NULL);
		pthread_join(th5, NULL);
		pthread_join(th2, NULL);
		pthread_join(th3, NULL);
	}
	
	doTSU_Release();
	printf("test finished...\n");

	return 0;
}

