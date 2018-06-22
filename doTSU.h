// Last Update:2018-06-22 19:55:00
/**
 * @file doTSU.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-21
 */

#ifndef DO_T_S_U_H
#define DO_T_S_U_H
#include <stdint.h>
#include <pthread.h>
#include <semaphore.h>
#include "aq.h"
#include "boe.h"
#include "msgc.h"



#define MAX_VTX_NUM_PER_BLOCK (100)
typedef struct VTX{
    sem_t   *sem;
    uint8_t *sig;
    uint8_t *pub;
}VTX;

typedef struct BlockTx{
    WMessage *wmsg;
    VTX *vtx_array[MAX_VTX_NUM_PER_BLOCK];
    int vtx_num;
}BlockTx;

typedef struct TSUContext{
    AtomicQ s_q; // wait to send data queue.
    AtomicQ r_q; // receive result queue.

    uint8_t th_flag;
    uint64_t last_tm;// timestamp us.
    MsgHandle msgHandle;
    void* userdata;
    MsgContext msgc;
    pthread_t s_thread;
    pthread_t r_thread;
}TSUContext;

BoeErr* doTSU_Init(TSUContext *ctx, char *r_devname, char *w_devname, MsgHandle msghandle, void*userdata);
BoeErr* doTSU_Release(TSUContext *ctx);
BoeErr* doTSU_RecoverPub(TSUContext *ctx, uint8_t *sig, uint8_t *result);
BoeErr* doTSU_GetHash(TSUContext *ctx, uint8_t *hash, uint8_t *next_hash);
#endif  /*DO_T_S_U_H*/
