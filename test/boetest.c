// Last Update:2018-08-13 20:59:30
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
#define TEST_NUMB 100050   //测试次数
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
    if(pidx >= gTotal)
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
            }
            else 
            {
                printf("bret ecode = %d, emsg = %s.\n", bret->ecode, bret->emsg);
            }
            gErrcnt++;
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
	char *data_path1 = argv[1];
	char *data_path2 = argv[2];
	char *data_path3 = argv[3];
	FILE *fd1;
	FILE *fd2;
	FILE *fd3;
    uint8_t  r[32],s[32],h[32],v, x[32], y[32];
	if (((fd1 = fopen(data_path1, "r")) == NULL)||((fd2 = fopen(data_path2, "r")) == NULL)||((fd3 = fopen(data_path3, "r")) == NULL))
	{
		printf("open data file error!!\n");
		exit(1);
	}

    while((gTotal <= 100000) && (!feof(fd1)) && (!feof(fd2))  && (!feof(fd3)))
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
    pthread_t th2;
    pthread_t th3;
    pthread_t th4;
    pthread_t th5;
    pthread_t th6;
    pthread_t th7;
    pthread_t th8;
    pthread_t th9;
    pthread_t th10;

    ret = pthread_create(&th1, NULL, test_ecc, NULL);
    ret = pthread_create(&th2, NULL, test_ecc, NULL);
    ret = pthread_create(&th3, NULL, test_ecc, NULL);
    ret = pthread_create(&th4, NULL, test_ecc, NULL);
    ret = pthread_create(&th5, NULL, test_ecc, NULL);
    ret = pthread_create(&th6, NULL, test_ecc, NULL);
    ret = pthread_create(&th7, NULL, test_ecc, NULL);
    ret = pthread_create(&th8, NULL, test_ecc, NULL);
    ret = pthread_create(&th9, NULL, test_ecc, NULL);
    ret = pthread_create(&th10, NULL, test_ecc, NULL);

	gettimeofday(&start, &tz);


	
    pthread_join(th1, NULL);
    pthread_join(th2, NULL);
    pthread_join(th3, NULL);
    pthread_join(th4, NULL);
    pthread_join(th5, NULL);
    pthread_join(th6, NULL);
    pthread_join(th7, NULL);
    pthread_join(th8, NULL);
    pthread_join(th9, NULL);
    pthread_join(th10, NULL);

	gettimeofday(&stop, &tz);
    {
        gettimeofday(&stop, NULL);
        duration = ((stop.tv_sec - start.tv_sec)*1000000 + stop.tv_usec - start.tv_usec)/1000;
        printf("ECDSA test finished,static results are fellow:\n");
        printf("ECDSA ERROR count : %d\n",gErrcnt);
        printf("ECDSA test time : %ldms\n",duration);

        return 0;
    }
	return 0;
}
static void get_hash_1(uint8_t *hash)
{
#if 0
	hash[0] = 0x44;
	hash[1] = 0x44;
	hash[2] = 0xba;
	hash[3] = 0x1d;
	hash[4] = 0x95;
	hash[5] = 0x14;
	hash[6] = 0x65;
	hash[7] = 0x51;
	hash[8] = 0x36;
	hash[9] = 0x8f;
	hash[10] = 0x6d;
	hash[11] = 0x05;
	hash[12] = 0x98;
	hash[13] = 0x38;
	hash[14] = 0x07;
	hash[15] = 0x43;
	hash[16] = 0x2e;
	hash[17] = 0x8e;
	hash[18] = 0x16;
	hash[19] = 0xd6;
	hash[20] = 0x1c;
	hash[21] = 0x3d;
	hash[22] = 0x92;
	hash[23] = 0x2a;
	hash[24] = 0x79;
	hash[25] = 0xe6;
	hash[26] = 0x8f;
	hash[27] = 0x29;
	hash[28] = 0x71;
	hash[29] = 0xfe;
	hash[30] = 0x42;
	hash[31] = 0x15;
#endif
    memset(hash, 0, 32);
    hash[31] = 0x11;
}
uint8_t emptyHash[32] = {0};
static void shex_dump_ln(unsigned char *buf, int len)
{
    for(int i =0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");

}

int main(int argc, char *argv[])
{
    BoeErr *ret = boe_init();
    unsigned char last_hash[32];
    unsigned char next_hash[32];
    if(ret != BOE_OK)
    {
        printf("init failed.\r\n");
        return 1;
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
    {
        get_hash_1(last_hash);
        for(int i = 0; i < 3; i++)
        {
            ret = boe_get_s_random(last_hash, next_hash);
            if(ret != BOE_OK)
            {
                printf("s_random failed, ecode:%d, emsg:%s\n", ret->ecode, ret->emsg);
            }
            else 
            {
                printf("last_hash:0x");
                shex_dump_ln(last_hash, sizeof(last_hash));
                printf("next_hash:0x");
                shex_dump_ln(next_hash, sizeof(next_hash));
                memcpy(last_hash, next_hash, sizeof(next_hash));
            }
            sleep(1);
        }
    }
    {
        // ecc test.
        ecdsa_test(argc, argv);

    }

    
    boe_release();

    return 0;
}

