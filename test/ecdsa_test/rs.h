// Last Update:2018-07-16 19:56:18
/**
 * @file rs.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-07-11
 */

#ifndef RS_H
#define RS_H
#include <stdint.h>
#include <linux/types.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/msg.h>


typedef struct RSContext{
    int sfd;
    int buflen;
    int type;
    struct ifreq req;
    uint8_t *tx_buf;
    uint8_t loc_mac[6];
    struct sockaddr_ll device;
}RSContext;
#define RS_MAX_PACKAGE_LEN (1000)
int RSCreate(char *ethname, int type, RSContext *ctx);
int RSRelease(RSContext *ctx);
int RSWrite(RSContext *ctx, uint8_t*p_data, int len);
int RSRead(RSContext *ctx, uint8_t*p_buf, int *len);
int RSSelect(RSContext *ctx, uint32_t timeout_ms);
#endif  /*RS_H*/
