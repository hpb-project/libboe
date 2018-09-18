// Last Update:2018-08-24 14:06:26
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
#define TEST_NUMB 100000   //测试次数
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
    }


    
    boe_release();

    return 0;
}

