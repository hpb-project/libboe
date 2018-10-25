// Last Update:2018-09-26 10:53:21
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

typedef struct Package{
	uint32_t pid;
	uint8_t  funcid;
	uint8_t  version;
	uint8_t  status;
	uint8_t  reserved;
	uint8_t  data[];
}Package;

static uint32_t get_pid()
{
	static uint32_t gpid = 0;
	return gpid++;
}
static void get_hash_1(uint8_t *hash)
{
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
}
uint8_t emptyHash[32] = {0};
static uint32_t hashCount = 0;
static uint8_t b_send_hash = 1;
static int mk_hash_pkg(uint8_t *last_hash, Package *p, uint32_t pid)
{
	p->pid = pid;
	p->funcid = 1;
	p->version = 0x10;
	p->status = 0;
	p->reserved = 0;
//	if(memcmp(emptyHash, last_hash, sizeof(emptyHash)) == 0)
//	{
//		get_hash_1(p->data);
//	}
//	else
	{
		memcpy(p->data, last_hash, sizeof(emptyHash));
	}
	return sizeof(Package) + 32;
}
static int make_ecc_package(Package*p, uint32_t pid, uint8_t *r, uint8_t*s,uint8_t *h, uint8_t v)
{
	p->pid = pid;
	p->funcid = 2;
	p->version = 0x10;
	p->status = 0;
	p->reserved = 0;
	memcpy(p->data+0, r, 32);
	memcpy(p->data+32, s, 32);
	memcpy(p->data+64, h, 32);
	p->data[96] = v;
	return sizeof(Package)+97;
}

static void dump_pkg(Package *p)
{
	printf("------- PKG info -------\n");
	printf("------- PKG info -------\n");
	printf("pid = 0x%x\n", p->pid);
	printf("sts = %d\n", p->status);
	printf("hah = 0x");
	for(int i = 0; i < 32; i++)
	{
		printf("%02x", p->data[i]);
	}
	printf("\n");
}
#define BUF_THR   20       //缓存门限
#define TEST_NUMB 100050   //测试次数
typedef struct xy_t{
	uint32_t x[32];
	uint32_t y[32];
}xy_t;

static xy_t xy_array[TEST_NUMB+1];
static uint8_t txa[1024];
static uint8_t rxa[1024];
static int ecdsa_test(RSContext *rs, int argc, char *argv[])
{
	char *data_path1 = argv[2];
	char *data_path2 = argv[3];
	char *data_path3 = argv[4];
	FILE *fd1;
	FILE *fd2;
	FILE *fd3;
	long   tx_cnt=0;
	long   rx_cnt=0;
	long   ok_cnt=0;
	long   er_cnt=0;
	long   bf_cnt=0;
	long   duration = 0;
	uint8_t  r[32],s[32],h[32],v;
	uint8_t last_hash[32];
	uint8_t  x,y,rx,ry,err;
	struct timeval start;
	struct timeval stop;
	struct timezone tz;
	int ret = 0, rlen = 0, wlen = 0;
	int i = 0;
	uint32_t pid = 0;
	rlen = sizeof(rxa);
	memset(last_hash, 0x0, sizeof(last_hash));
    printf("-------------- start ecdsa test -------------------\n");

	if (((fd1 = fopen(data_path1, "r")) == NULL)||((fd2 = fopen(data_path2, "r")) == NULL)||((fd3 = fopen(data_path3, "r")) == NULL))
	{
		printf("open data file error!!\n");
		exit(1);
	}
	gettimeofday(&start, &tz);

	while(1)
	{
		while((tx_cnt<TEST_NUMB)&&(bf_cnt<BUF_THR))
		{
			rlen = sizeof(rxa);
			wlen = sizeof(txa);
			pid = get_pid();
			memset(txa, 0x0, sizeof(txa));
			memset(rxa, 0x0, sizeof(rxa));
			Package *p = (Package*)txa;
			//if((pid == 50000) && b_send_hash == 1)
			if(1 && (b_send_hash == 1))
			{
				// send random.
				wlen = mk_hash_pkg(last_hash, p, pid);
				dump_pkg(p);
				if(RSWrite(rs, txa, wlen) < 0)
				{
					printf("RSWrite failed.\n");
					exit(-1);
				}
				b_send_hash = 0;
				hashCount++;
				//sleep(1);
			}
#if 0
			else
			{
				if(feof(fd1))
				{
					fseek(fd1,0,SEEK_SET);
				}
				if(feof(fd2))
				{
					fseek(fd2,0,SEEK_SET);
				}
				//读取一组数据并发送
				for(i=0;i<32;i++)
				{
					fscanf(fd1,"%hhu,%hhu,%hhu\n",&r[i],&s[i],&h[i]);
				}
				fscanf(fd2,"%hhu\n",&v);
				if(feof(fd3))
				{
					fseek(fd3,0,SEEK_SET);
				}


				//填充发送帧并插错
				if((tx_cnt % 419)==0)
				{
					r[31]^=0xff;
				}//238
				if((tx_cnt % 413)==0)
				{
					s[31]^=0xff;
				}//242
				if((tx_cnt % 457)==0)
				{
					h[31]^=0xff;
				}//218
				// make package

				wlen = make_ecc_package(p, pid, r, s,h, v);
				if(RSWrite(rs, txa, wlen) < 0)
				{
					printf("RSWrite failed.\n");
					break;
				}
				//填充发送帧并插错
				if(((tx_cnt % 419) == 0)  ||
						((tx_cnt % 413)==0)   ||
						((tx_cnt % 457)==0))
				{
					printf("pid = %d should be error.\r\n", p->pid);
				}
				for(i=0;i<32;i++)
				{
					fscanf(fd3,"%hhu,%hhu\n",&x,&y);
					xy_array[(int)p->pid].x[i]=x;
					xy_array[(int)p->pid].y[i]=y;
				}
				tx_cnt++;
			}
#endif

			bf_cnt++;
		}
		ret = RSSelect(rs, 4000);
		rlen = sizeof(rxa);
		if(ret > 0)
		{
			ret = RSRead(rs, rxa, &rlen);
			if(ret < 0)
			{
				printf("RSRead failed.\n");
				break;
			}
			else
			{
				Package *p = (Package*)rxa;
				if(p->funcid == 2)
				{
					rx_cnt++;

					//公钥比较
					if(p->pid > TEST_NUMB || p->pid < 0)
					{
						printf("receive package pid error, %d.\r\n", p->pid);
					}
					else
					{
						err=0;
						for(i=0;i<32;i++)
						{
							x = xy_array[p->pid].x[i];
							y = xy_array[p->pid].y[i];
							rx=p->data[i];
							ry=p->data[32+i];
							if((x!=rx)||(y!=ry))
							{
								err++;
							}
						}
						if(err>0)
						{
							er_cnt++;
							printf("rq_seq=%d is error.\n", p->pid);
						}
					}
				}
				else if(p->funcid == 1)
				{
					printf("receive hash package.\r\n");
					dump_pkg(p);
					memcpy(last_hash, p->data, sizeof(emptyHash));
					b_send_hash = 1;
				}
                else
                {
                    printf("unknown response.\n");
                }
				bf_cnt--;

			}
		}
        else if(ret == 0)
        {
            // timeout
            printf("ecc transport failed.\n");
            return 1;
        }

		if((tx_cnt==TEST_NUMB)&&(rx_cnt==TEST_NUMB))
		{
			gettimeofday(&stop, &tz);
			duration = ((stop.tv_sec - start.tv_sec)*1000000 + stop.tv_usec - start.tv_usec)/1000;
			printf("ECDSA test finished,static results are fellow:\n");
			printf("tx ECDSA test data count : %ld\n",tx_cnt);
			printf("rx ECDSA reply count : %ld\n",rx_cnt);
			printf("ECDSA ERROR count : %ld\n",er_cnt);
			printf("ECDSA test time : %ldms\n",duration);
			printf("test random count : %d\n", hashCount);
			fclose(fd1);
			fclose(fd2);
			fclose(fd3);
            if(er_cnt == 699)
            {
                printf("ecc test failed.\n");
                return 0;
            }
            else
            {
                printf("ecc test ok.\n");
                return 1;
            }
			return 0;
		}
	}
	return 0;
}

static int hash_test(RSContext *rs, int argc, char *argv[])
{
	long   tx_cnt=0;
	long   rx_cnt=0;
	long   ok_cnt=0;
	long   er_cnt=0;
	long   bf_cnt=0;
	long   duration = 0;
	uint8_t  r[32],s[32],h[32],v;
	uint8_t last_hash[32];
	uint8_t  x,y,rx,ry,err;
	struct timeval start;
	struct timeval stop;
	struct timezone tz;
	int ret = 0, rlen = 0, wlen = 0;
	int i = 0;
	uint32_t pid = 0;
    int testnum = 10;
	rlen = sizeof(rxa);
	memset(last_hash, 0x0, sizeof(last_hash));
    printf("-------------- start ecdsa test -------------------\n");

	gettimeofday(&start, &tz);

	while(1)
	{
		while((tx_cnt<testnum)&&(bf_cnt<BUF_THR))
		{
			rlen = sizeof(rxa);
			wlen = sizeof(txa);
			pid = get_pid();
			memset(txa, 0x0, sizeof(txa));
			memset(rxa, 0x0, sizeof(rxa));
			Package *p = (Package*)txa;
			//if((pid == 50000) && b_send_hash == 1)
			if(1 && (b_send_hash == 1))
			{
				// send random.
				wlen = mk_hash_pkg(last_hash, p, pid);
				dump_pkg(p);
				if(RSWrite(rs, txa, wlen) < 0)
				{
					printf("RSWrite failed.\n");
					exit(-1);
				}
				b_send_hash = 0;
				hashCount++;
			}

			bf_cnt++;
		}
		ret = RSSelect(rs, 4000);
		rlen = sizeof(rxa);
		if(ret > 0)
		{
			ret = RSRead(rs, rxa, &rlen);
			if(ret < 0)
			{
				printf("RSRead failed.\n");
				break;
			}
			else
			{
				Package *p = (Package*)rxa;
                if(p->funcid == 1)
				{
					printf("receive hash package.\r\n");
					dump_pkg(p);
					memcpy(last_hash, p->data, sizeof(emptyHash));
					b_send_hash = 1;
				}
                else
                {
                    printf("unknown response.\n");
                }
				bf_cnt--;

			}
		}
        else if(ret == 0)
        {
            // timeout
            printf("transport failed.\n");
            return 1;
        }

		if((tx_cnt==testnum)&&(rx_cnt==testnum))
		{
			return 0;
		}
	}
	return 0;
}
int main(int argc, char *argv[])
{
	char *ethname;
	int type, ret;
	type = 0xFF01;
	ethname = argv[1];
	RSContext rs;
	ret = RSCreate(ethname, type, &rs);
    if(ret != 0)
    {
        printf("rscreate error\n");
        return 1;
    }

	//ret = ecdsa_test(&rs, argc, argv);
	ret = hash_test(&rs, argc, argv);

	RSRelease(&rs);

	return ret;
}
