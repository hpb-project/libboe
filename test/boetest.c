// Last Update:2018-10-22 16:01:22
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

#define BUF_THR   20       //缓存门限
#define TEST_NUMB 10000   //测试次数

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

static rsv_t rsv_array[TEST_NUMB+1];
static uint32_t gTotal = 0;
static uint32_t gErrcnt = 0;
static volatile int gCurrent = 0;
int get_data(rsv_t **data)
{
	int pidx = gCurrent++;
	if((pidx >= TEST_NUMB) || (pidx >= gTotal))
	{
		return -1;
	}
	*data = &rsv_array[pidx];
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
		if (0 == get_data(&pdata)){
			memcpy(sig+0, pdata->r, 32);
			memcpy(sig+32, pdata->s, 32);
			memcpy(sig+64, pdata->h, 32);
			sig[96] = pdata->v;
			BoeErr *bret = boe_valid_sign(sig, pub);
			if(bret == BOE_OK)
			{
				if(memcmp(pdata->x, pub, 32) == 0 &&
						memcmp(pdata->y, pub+32, 32) == 0)
				{
					continue;
				}
				else
				{
					printf("pubkey compare failed.\n");
				}
			}
			else
			{
				printf("msg send/receive failed.\n");
			}
			gErrcnt++;
			printf("ecctest current = %d.\n",gCurrent);
		}
		else
		{
			break;
		}
	}
	printf("thread exit.\n");
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

	while((gTotal < TEST_NUMB) && (!feof(fd1)) && (!feof(fd2))  && (!feof(fd3)))
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
static int ecdsa_test(int argc, char *argv[])
{
	long   duration = 0;

	uint8_t  rx,ry,err;
	struct timeval start;
	struct timeval stop;
	struct timezone tz;
	int ret = 0, rlen = 0, wlen = 0;
	int i = 0;
	// read all data to array.
	load_data(argc, argv);
	pthread_t th1;
	//pthread_t th2;
	//pthread_t th3;
	//pthread_t th4;
	//pthread_t th5;
	//pthread_t th6;
	//pthread_t th7;
	//pthread_t th8;
	//pthread_t th9;
	//pthread_t th10;

	ret = pthread_create(&th1, NULL, test_ecc, NULL);
	//ret = pthread_create(&th2, NULL, test_ecc, NULL);
	//ret = pthread_create(&th3, NULL, test_ecc, NULL);
	//ret = pthread_create(&th4, NULL, test_ecc, NULL);
	//ret = pthread_create(&th5, NULL, test_ecc, NULL);
	//ret = pthread_create(&th6, NULL, test_ecc, NULL);
	//ret = pthread_create(&th7, NULL, test_ecc, NULL);
	//ret = pthread_create(&th8, NULL, test_ecc, NULL);
	//ret = pthread_create(&th9, NULL, test_ecc, NULL);
	//ret = pthread_create(&th10, NULL, test_ecc, NULL);

	gettimeofday(&start, &tz);



	pthread_join(th1, NULL);
	//pthread_join(th2, NULL);
	//pthread_join(th3, NULL);
	//pthread_join(th4, NULL);
	//pthread_join(th5, NULL);
	//pthread_join(th6, NULL);
	//pthread_join(th7, NULL);
	//pthread_join(th8, NULL);
	//pthread_join(th9, NULL);
	//pthread_join(th10, NULL);

	gettimeofday(&stop, &tz);
	{
		gettimeofday(&stop, NULL);
		duration = ((stop.tv_sec - start.tv_sec)*1000000 + stop.tv_usec - start.tv_usec)/1000;
		printf("ECDSA test finished,static results are fellow:\n");
		printf("ECDSA ERROR count : %d\n",gErrcnt);
		printf("ECDSA test time : %ldms\n",duration);
		if(gErrcnt != 0)
		{
			printf("ECDSA Error count : %d\n", gErrcnt);
			return 1;
		}

	}
	return 0;
}

static void shex_dump_ln(unsigned char *buf, int len)
{
	for(int i =0; i < len; i++)
	{
		printf("%02x", buf[i]);
	}
	printf("\n");

}

static int hwsigntest(void)
{
	unsigned char random[32];
	unsigned char sig[64];

	BoeErr *ret = boe_get_random(random);
	if(ret != BOE_OK)
	{
		printf("get random failed.\n");
		return 1;
	}
	unsigned int i = 0;

	while(i < 3)
	{
		ret = boe_hw_sign(random, sig);
		i++;
		if(ret != BOE_OK)
		{
			return 1;

			printf("get hw sign failed, i = %u.\n", i);
		}
		usleep(200000);
	}
	return 0;
}

#define HASH_TEST_COUNT 10 
/*
static const char *hash_serial_v1 [HASH_TEST_COUNT] = {
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
*/

static const char *hash_serial_v1 [HASH_TEST_COUNT] = {
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

static int hash_test()
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
	    printf("\n");
	    printf("##### hash get loop [%d] #####\n",i);
	    printf("pre_hash=");
	    shex_dump_ln(last, sizeof(last));

	    BoeErr *ret = boe_get_n_random(last, shash);
	    if(ret != BOE_OK)
	    {
	        printf("boe_get_s_random failed,error ecode = %d\n",ret->ecode);
	        if(BOE_HASH_TIME_LIMIT == ret)
	        {
	            printf("get hash time limite, sleep 5s continue \n");
	            sleep(5);
	            i = i - 1;
	            continue;
	        }
	    }
	    else
	    {
	        printf("get hash=");
	        shex_dump_ln(shash, sizeof(shash));
	        printf("get hash ok p_status = %d\n",p_status);
	    }

	    memset(hash_str, 0, sizeof(hash_str));
	    hash_to_string(shash, hash_str);

	    if(strcmp(hash_str, hash_serial_v1[i]) != 0)
	    {
	        printf("last = ");
	        shex_dump_ln(last, sizeof(last));
	        printf("hash = ");
	        shex_dump_ln(shash, sizeof(shash));

	        printf("get random not matched with %s.\n", hash_serial_v1[i]);
	        return 1;
	    }
	    else
	    {
	        printf("\n");
	        printf("&&&&& hash check loop [%d] &&&\n",i);
	        ret = boe_check_random(last, shash);
	        if(ret != BOE_OK)
	        {
	            printf("boe_check_random failed,error code = %d\n",ret->ecode);
	        }
	        else
	        {
	            printf("boe_check_random ok\n");
	        }
	    }
	    memcpy(last, shash, sizeof(shash));
	}
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
	BoeErr *ret = boe_test_init(ethname);
	if(ret != BOE_OK)
	{
		printf("init failed.\r\n");
		return 1;
	}
	else
	{
		printf("init ok.\r\n");
	}
	ret = boe_hw_check();
	if(ret != BOE_OK)
	{
		printf("hw check failed.\r\n");
		return 1;
	}
	else
	{
		printf("hw check success.\r\n");
	}
#if 0
	{
		// phy test.
		unsigned int reg_02 = 0x02;
		unsigned int reg_03 = 0x03;
		unsigned int val_02 = 0;
		unsigned int val_03 = 0;
		unsigned int val_s  = 0;
		ret = boe_phy_read(reg_02, &val_02);
		if(ret != BOE_OK)
		{
			printf("read phy 0x02 register failed.\r\n");
			return 1;
		}
		printf("reg_0x02 = 0x%02x.\n", val_02);
		ret = boe_phy_read(reg_03, &val_03);
		if(ret != BOE_OK)
		{
			printf("read phy 0x03 register failed.\r\n");
			return 1;
		}
		printf("reg_0x03 = 0x%02x.\n", val_03);
		ret = boe_phy_shd_read(0x1c, 0x1F, &val_s);
		if(ret != BOE_OK)
		{
			printf("read phy shd register failed.\r\n");
			return 1;
		}
		printf("reg_1C = 0x%02x.\n", val_s);
		if((val_02 == 0x0020) && ((val_03 & 0xFFF0)==0x60C0) &&
				((val_s & 0x06) == 0x04))
		{
			printf("phy is ok.\r\n");
		}
		else{
			printf("phy is error.\r\n");
			return 1;
		}
	}
#endif
	{
		// ecc test.
		if(0 == ecdsa_test(argc, argv))
		{
		    printf("ecc test ok.\n");
		}
		else
		{
		    printf("ecc test failed.\n");
		    return 1;
		}
		// hash test 
		if(0 == hash_test())
		{
			printf("hash test ok.\n");
		}
		else
		{
			printf("hash test failed.\n");
			return 3;
		}
		if(0 == hwsigntest())
		{
			printf("hwsigntest ok.\n");
		}
		else 
		{
			printf("hwsigntest failed.\n");
		}
	}

	boe_release();

	return 0;
}

