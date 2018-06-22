// Last Update:2018-06-22 19:52:36
/**
 * @file doTSU.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-21
 */
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include "tsu_connector.h"
#include "doTSU.h"
#include "msgc.h"
#include "boe.h"
#include "error.h"


#define TX_SIG_LEN (97)
#define TX_PUB_LEN (64)

static int gShortTimeout = 100000; // 100ms
static int gLongTimeout = 5000000; // 5s

VTX* vtx_new(uint8_t*sig, uint8_t*pub)
{
    VTX *v = (VTX*)malloc(sizeof(VTX));
    v->sem = (sem_t*)malloc(sizeof(sem_t));
    sem_init(v->sem, 0, 0);
    v->sig = sig;
    v->pub = pub;
    return v;
}

void vtx_free(VTX *v)
{
    sem_destroy(v->sem);
    free(v->sem);
    free(v);
}

BlockTx* btx_new()
{
    BlockTx *b = (BlockTx*)malloc(sizeof(BlockTx));
    if(b)
    {
        memset(b, 0, sizeof(BlockTx));
    }
    return b;
}

void btx_release(BlockTx* b)
{
    if(b)
    {
        if(b->vtx_array)
            free(b->vtx_array);
        if(b->wmsg)
            WMessageFree(b->wmsg);
    }
}

int tsu_check_response(uint8_t* data, int plen, uint32_t uid)
{
    T_Package *p = (T_Package*)data;
    if(p->sequence == uid && p->is_response == 1)
        return 1;
    return 0;
}

static void* s_thread(void* userdata)
{
    TSUContext *ctx = (TSUContext*)userdata;
    int now_ts;
    uint64_t timeout = 20000;// 20ms
    while(ctx->th_flag == 0) ;
    while(ctx->th_flag == 1)
    {
        int num = aq_len(&ctx->s_q);
        int cnt = 0;
        now_ts = get_timestamp_us();
        if((now_ts - ctx->last_tm) > timeout || 
                num >= MAX_VTX_NUM_PER_BLOCK)
        {
            num = num > MAX_VTX_NUM_PER_BLOCK ? MAX_VTX_NUM_PER_BLOCK : num;
            BlockTx b;
            VTX *v = NULL;
            AQData *d = NULL;

            while(cnt < num)
            {
                d = aq_pop(&ctx->s_q);
                if( d == NULL)
                {
                    break;
                }
                b.vtx_array[cnt] = (VTX*)d->buf;
                b.vtx_num++;
                cnt++;
            }
            T_Package *p = tsu_package_new(FUNCTION_ECSDA_CHECK, cnt*TX_SIG_LEN);
            for(num = 0; num < b.vtx_num; num++)
            {
                tsu_set_data(p, TX_SIG_LEN*num, b.vtx_array[num]->sig, TX_SIG_LEN);
            }
            tsu_finish_package(p);

            b.wmsg = WMessageNew(p->sequence, tsu_check_response, gLongTimeout, (uint8_t*)p, tsu_package_len(p));
            if(b.wmsg != NULL)
            {
                AQData * sd = aqd_new(sizeof(BlockTx));
                memcpy(sd->buf, &b, sizeof(BlockTx));
                aq_push(&ctx->r_q, sd);
                msgc_send(&ctx->msgc, b.wmsg);
            }
            free(p);
        }
        else
        {
            usleep(timeout/10);
        }
    }
    {
        AQData *d = NULL;
        while((d=aq_pop(&ctx->s_q)) != NULL)
        {
            VTX *v =  (VTX*)d->buf;
            sem_post(v->sem);
            aqd_free(d);
        }
        ctx->th_flag = 3;
    }
    return NULL;
}

static void* r_thread(void* userdata)
{
    TSUContext *ctx = (TSUContext*)userdata;
    int now_ts;
    uint64_t timeout = 20000;// 20ms
    while(ctx->th_flag == 0) ;
    while(ctx->th_flag == 1)
    {
        AQData *d = aq_pop(&ctx->r_q);
        if(d != NULL)
        {
            BlockTx *b = (BlockTx*)d->buf;
            AQData *rd = msgc_read(&ctx->msgc, b->wmsg);
            if(rd != NULL)
            {
                T_Package * p = (T_Package*)rd->buf;
                int rcnt = p->length / TX_PUB_LEN;
                if(rcnt == b->vtx_num)
                {
                    for(int i = 0; i < rcnt; i++)
                    {
                        memcpy(b->vtx_array[i]->pub,p->payload+i*TX_PUB_LEN, TX_PUB_LEN);
                        sem_post(&(b->vtx_array[i]->sem));
                    }
                }
                aqd_free(rd);
            }
            btx_release(b);
            aqd_free(d);
        }
        else
        {
            usleep(timeout/10);
        }
    }
    while(ctx->th_flag != 3) 
        usleep(100); // wait s_thread finished.

    {
        AQData *d = NULL;
        while((d = aq_pop(&ctx->r_q)) != NULL)
        {
            BlockTx *b = (BlockTx*)d->buf;
            AQData *rd = msgc_read(&ctx->msgc, b->wmsg);
            if(rd != NULL)
            {
                T_Package * p = (T_Package*)rd->buf;
                int rcnt = p->length / TX_PUB_LEN;
                if(rcnt == b->vtx_num)
                {
                    for(int i = 0; i < rcnt; i++)
                    {
                        memcpy(b->vtx_array[i]->pub,p->payload+i*TX_PUB_LEN, TX_PUB_LEN);
                        sem_post((b->vtx_array[i]->sem));
                    }
                }
                aqd_free(rd);
            }
            btx_release(b);
            aqd_free(d);
        }
    }

    return NULL;
}

static int tsu_msg_handle(uint8_t *data, int len, void*userdata)
{
    // no need do.
    return 0;
}

BoeErr* doTSU_Init(TSUContext *ctx, char *r_devname, char *w_devname, MsgHandle msghandle, void*userdata)
{
    ctx->userdata = userdata;
    ctx->msgHandle = msghandle;
    ctx->th_flag = 0;
    aq_init(&ctx->s_q, 1000000);
    aq_init(&ctx->r_q, 1000000);
    int ret = msgc_init(&ctx->msgc, r_devname, w_devname, tsu_msg_handle, (void*)ctx);
    if(ret != 0)
        return &e_init_fail;
    ret = pthread_create(&ctx->s_thread, NULL, s_thread, (void*)ctx);
    ret = pthread_create(&ctx->r_thread, NULL, r_thread, (void*)ctx);
    ctx->th_flag = 1;
    return &e_ok;
}

BoeErr* doTSU_Release(TSUContext *ctx)
{
    ctx->th_flag = 2; 

    // first wait s_thread.
    pthread_join(ctx->s_thread, NULL);
    pthread_join(ctx->r_thread, NULL);
    aq_free(&ctx->s_q);
    aq_free(&ctx->r_q);
    msgc_release(&ctx->msgc);

    return &e_ok;
}

BoeErr* doTSU_RecoverPub(TSUContext *ctx, uint8_t *sig, uint8_t *pub)
{
    VTX *v = vtx_new(sig, pub);
    AQData *d = aqd_new(sizeof(VTX));
    memcpy(d->buf, v, sizeof(VTX));
    aq_push(&ctx->s_q, d);
    sem_wait(v->sem);
    vtx_free(v);
    return &e_ok;
}

BoeErr* doTSU_GetHash(TSUContext *ctx, uint8_t *hash, uint8_t *next_hash)
{
    T_Package *p = tsu_package_new(FUNCTION_GEN_HASH, 256);
    tsu_set_data(p, 0, hash, 256);
    tsu_finish_package(p);
    WMessage *wm = WMessageNew(p->sequence, tsu_check_response, gLongTimeout, (uint8_t*)p, tsu_package_len(p));
    msgc_send(&ctx->msgc, wm);
    free(p);

    AQData *d = msgc_read(&ctx->msgc, wm);
    if(d != NULL)
    {
        T_Package *r = (T_Package*)d->buf;
        memcpy(next_hash, r->payload, 256);
        aqd_free(d);
        return &e_ok;
    }
    return &e_result_invalid;
}
