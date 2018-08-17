// Last Update:2018-07-16 19:43:59
/**
 * @file rawsocket.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-07-11
 */

#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/msg.h>


#include "rs.h"



static uint8_t  rmt_mac[6]={0x7F,0xFF,0xFF,0xFF,0xFF,0xFF};                      //远端mac地址
#define max_package_len (RS_MAX_PACKAGE_LEN)
#define package_header_len (sizeof(struct ethhdr))

int RSCreate(char *ethname, int type, RSContext *ctx)
{
	int sockfd;
	int  if_index;                        //网卡索引
	struct ifreq *req;                       //网卡操作
	struct sockaddr_ll *device;            //链路层地址结构
	struct ethhdr *whdr = NULL;

    memset(ctx, 0x0, sizeof(RSContext));
    ctx->type = type;
    ctx->buflen = max_package_len + sizeof(struct ethhdr);
    ctx->tx_buf = (uint8_t*) malloc(ctx->buflen);
    if(ctx->tx_buf == NULL)
    {
		printf("memory not enough !!\n");
        goto failed;
    }
    memset(ctx->tx_buf, 0x0, ctx->buflen);
    whdr = (struct ethhdr*)ctx->tx_buf;
    req = &ctx->req;
    device = &ctx->device;

	//1:建立raw socket
	if ((ctx->sfd = socket(AF_PACKET, SOCK_RAW, htons(type)))== -1)
	{
		printf("raw sokcet set up fail !!\n");
        goto failed;
	}
    sockfd = ctx->sfd;


	//2:得到本机网口信息
	strcpy( req->ifr_name, ethname );
	if ( ioctl( sockfd, SIOCGIFFLAGS, req ) < 0 )
	{
		printf( "failed to do ioctl!" );
        goto failed;
	}
	if ( ioctl(sockfd, SIOCGIFHWADDR, req) < 0 )
	{
		printf( "failed to do netif ioctl!!%m\n" );
        goto failed;
	}
	memcpy( ctx->loc_mac, req->ifr_hwaddr.sa_data, 6 );  //得到本地网卡地址
	if ( ioctl( sockfd, SIOCGIFINDEX, req ) < 0 )
	{
		printf( "failed to get IF hw address index!!\n" );
        goto failed;
	}

	if_index = req->ifr_ifindex;  //得到本地网卡索引
	//设置发送device结构体
	memset(device,0,sizeof(struct sockaddr_ll));
	device->sll_ifindex = if_index;
	device->sll_family  = AF_PACKET;

	memcpy(device->sll_addr, ctx->loc_mac, 6);
	device->sll_halen = htons(6);
    device->sll_protocol = htons(type);

    if( bind(sockfd, (struct sockaddr*)device, sizeof(struct sockaddr_ll)) < 0)
    {
        printf("Socket Bind error.\n");
        goto failed;
    }

	//4:初始化发送包
	memcpy(whdr->h_dest, rmt_mac, 6);
	memcpy(whdr->h_source, ctx->loc_mac, 6);
	whdr->h_proto = htons(type);
    return 0;

failed:
    if(ctx)
    {
        if (ctx->sfd > 0)
            close(ctx->sfd);
        if(ctx->tx_buf != NULL)
            free(ctx->tx_buf);
        memset(ctx, 0x0, sizeof(RSContext));
    }
    return -1;
}

int RSRelease(RSContext *ctx)
{
    if(ctx)
    {
        if (ctx->sfd > 0)
            close(ctx->sfd);
        if(ctx->tx_buf != NULL)
            free(ctx->tx_buf);
        memset(ctx, 0x0, sizeof(RSContext));
    }
    return 0;
}

int RSWrite(RSContext *ctx, uint8_t*p_data, int len)
{
    int tx_len = 0;
    if(!ctx)
        return -1;
    if(len > max_package_len)
        return -1;
    memcpy(ctx->tx_buf + sizeof(struct ethhdr), p_data, len);
    int pkg_len = len + sizeof(struct ethhdr);
    tx_len = sendto (ctx->sfd, ctx->tx_buf, pkg_len, 0, (struct sockaddr *) &ctx->device, sizeof (ctx->device));
    if(tx_len != pkg_len)
        return -1;
    return 0;
}

static int checkpack(RSContext *ctx, struct ethhdr *eth)
{
	if(ntohs(eth->h_proto) == ctx->type)
        return 1;
    else
        return 0;
}

int RSRead(RSContext *ctx, uint8_t*p_buf, int *len)
{
    int rx_len = 0;
    uint8_t pdata[max_package_len+package_header_len];
    rx_len = recvfrom(ctx->sfd, pdata, max_package_len+package_header_len, 0, NULL, NULL);
    if(rx_len<=package_header_len || (checkpack(ctx, (struct ethhdr *)pdata) == 0))
        return -1;

    rx_len -= package_header_len;
    if(rx_len < *len)
        *len = rx_len;

    memcpy(p_buf, pdata+package_header_len, *len);
    return 0;
}


/*
 * return value:
 *   == 0: timeout 
 *   >  0: get msg
 *   <  0: failed
 */ 
int RSSelect(RSContext *ctx, uint32_t timeout_ms)
{
    int maxfd = 0;
    struct timeval tv;
    fd_set rfds;
    if(!ctx)
        return -1;

    FD_ZERO(&rfds);
    FD_SET(ctx->sfd, &rfds);
    maxfd = ctx->sfd + 1;
    tv.tv_sec  = timeout_ms/1000;
    tv.tv_usec = (timeout_ms%1000) * 1000;

    int ret = select(maxfd, &rfds, NULL, NULL, &tv);
    return ret;
}
