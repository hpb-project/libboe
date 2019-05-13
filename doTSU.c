// Last Update:2019-03-12 20:00:22
/**
 * @file doTSU.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-21
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include "tsu_connector.h"
#include "doTSU.h"
#include "msgc.h"
#include "serror.h"
#include "common.h"


typedef struct TSUContext{
	AsyncCallback asyncCallback;
	void *userdata;
    RSContext  rs;
    MsgContext msgc;
}TSUContext;

static TSUContext gTsu;

#define TSU_RV (0xFF01)

#define TX_SIG_LEN (97)
#define TX_PUB_LEN (64)
#define TSU_HASH_LEN (32)

static int gShortTimeout = 150; // 100ms

int tsu_check_response(uint8_t* data, int plen, uint32_t uid)
{
    T_Package *p = (T_Package*)data;
    if(p->sequence == uid)
        return 1;
    return 0;
}

static int tsu_msg_handle(uint8_t *data, int len, void*userdata)
{
    // no need do.
    return 0;
}

static int tsu_msg_callback(WMessage *m, void*userdata)
{
	TSUContext *ctx = &gTsu;

    T_Package *tsu_packet = NULL;
    T_Package *tsu_packet_old = NULL;

	if(ctx->asyncCallback != NULL)
	{
        tsu_packet_old =  (T_Package *)(m->s.buf);
        int type = tsu_packet_old->function_id;
		if(m->d == NULL)
		{
			ctx->asyncCallback(type, NULL, 0, m->userdata, m->userdata_len, tsu_packet_old->payload, ctx->userdata);
		}
		else
		{
            tsu_packet = (T_Package *)(m->d->buf);
			ctx->asyncCallback(type, tsu_packet->payload, m->d->len, m->userdata, m->userdata_len, tsu_packet_old->payload, ctx->userdata);
		}
	}

    return 0;
}

void doTSU_RegisAsyncCallback(AsyncCallback afun, void *data)
{
	TSUContext *ctx = &gTsu;
	ctx->asyncCallback = afun;
	ctx->userdata = data;
}

BoeErr* doTSU_Init(char *ethname, MsgHandle msghandle, void*userdata)
{
    TSUContext *ctx = &gTsu;
    int ret = RSCreate(ethname, TSU_RV, &ctx->rs);
    if(ret != 0)
    {
        return &e_init_fail;
    }
    ret = msgc_init(&ctx->msgc, &ctx->rs, tsu_msg_handle, (void*)ctx, tsu_msg_callback);
    if(ret != 0)
    {
        RSRelease(&ctx->rs);
        return &e_init_fail;
    }
    return &e_ok;
}

BoeErr* doTSU_Release()
{
    TSUContext *ctx = &gTsu;
    msgc_release(&ctx->msgc);

    return &e_ok;
}

T_Package *make_query_recover_key(uint8_t *sig, int *len)
{
    T_Package *p = tsu_package_new(FUNCTION_ECSDA_CHECK, TX_SIG_LEN);
    if(p)
    {
        tsu_set_data(p, 0, sig, TX_SIG_LEN);
        tsu_finish_package(p);
        *len = TX_SIG_LEN + sizeof(T_Package);
    }

    return p;
}

T_Package *make_query_get_hash(uint8_t *hash, int *len)
{
    T_Package *p = tsu_package_new(FUNCTION_GEN_NEW_HASH, TSU_HASH_LEN);
    if(p)
    {
        tsu_set_data(p, 0, hash, TSU_HASH_LEN);
        tsu_finish_package(p);
        *len = TSU_HASH_LEN + sizeof(T_Package);
    }

    return p;
}

T_Package *make_query_get_new_hash(uint8_t *hash, int *len)
{
    T_Package *p = tsu_package_new(FUNCTION_GEN_NEW_HASH, TSU_HASH_LEN);
    if(p)
    {
        tsu_set_data(p, 0, hash, TSU_HASH_LEN);
        tsu_finish_package(p);
        *len = TSU_HASH_LEN + sizeof(T_Package);
    }

    return p;
}

T_Package *make_query_check_hash(uint8_t *pre_hash, uint8_t *hash, int *len)
{
    T_Package *p = tsu_package_new(FUNCTION_GEN_NEW_HASH, TSU_HASH_CHECK_LEN);
    if(p)
    {
    
        tsu_set_data(p, 0, pre_hash, TSU_HASH_LEN);
        tsu_set_data(p, TSU_HASH_LEN, hash, TSU_HASH_LEN);
        tsu_finish_package(p);
        *len = TSU_HASH_CHECK_LEN +sizeof(T_Package);
    }

    return p;
}

static BoeErr* doCommand(T_Package *p, AQData **d, int timeout, int wlen)
{
    MsgContext *wqc = &gTsu.msgc;
    WMessage * wm = WMessageNew(p->sequence, tsu_check_response, timeout, (uint8_t*)p, wlen, 0);
    if(msgc_send_async(wqc, wm) == 0)
    {
        AQData *q = msgc_read(wqc, wm);
        if(q == NULL || q->buf == NULL)
            return &e_msgc_read_timeout;
        *d = q;
        return &e_ok;
    }
    else
    {
        return &e_msgc_send_fail;
    }
}
#if 1
/*recover pub*/
static BoeErr* doCommandRecoverPubAsync(T_Package *p, int timeout, int wlen, unsigned char *param, int param_len)
{
    MsgContext *wqc = &gTsu.msgc;
    WMessage * wm = WMessageNew(p->sequence, tsu_check_response, timeout, (uint8_t*)p, wlen, 1);
    WMessageAddUserdata(wm, param, param_len);
	
    if(msgc_send_async(wqc, wm) == 0)
    {
        return &e_ok;
    }
    else
    {
        return &e_msgc_send_fail;
    }
}
BoeErr* doTSU_RecoverPub_Async(uint8_t *sig, unsigned char *param, int param_len)
{
    int wlen = 0;
    T_Package *p = make_query_recover_key(sig, &wlen);
    BoeErr *ret = NULL;
    if(p)
    {
        ret = doCommandRecoverPubAsync(p, gShortTimeout, wlen, param, param_len);
        free(p);
        if(ret == &e_ok)
        {
            return &e_ok;
        }
		 else
		 {
			printf("doCommandRecoverPubAsync error %d\n",ret->ecode);
		 }
    }
    else
    {
        return &e_no_mem;
    }
    return &e_ok;
}
#endif
BoeErr* doTSU_RecoverPub(uint8_t *sig, uint8_t *pub)
{
    int wlen = 0;
    T_Package *p = make_query_recover_key(sig, &wlen);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        int try = 3;
        do{
            ret = doCommand(p, &r, gShortTimeout, wlen);
            if(ret == &e_msgc_read_timeout)
                try--;
            else
                break;
        }while(try > 0);

        free(p);
        if(ret == &e_ok)
        {
            T_Package *q = (T_Package*)r->buf;
            memcpy(pub, q->payload, TX_PUB_LEN);
            aqd_free(r);
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
    return &e_ok;
}

BoeErr* doTSU_GetHash(uint8_t *hash, uint8_t *next_hash)
{
	int wlen = 0;
	T_Package *p = make_query_get_hash(hash, &wlen);
	BoeErr *ret = NULL;
	AQData *r = NULL;
	int try = 3;
	
	if(p)
	{
	    do{
	        ret = doCommand(p, &r, gShortTimeout, wlen);
	        if(ret == &e_msgc_read_timeout)
	           try --;
	        else
	            break;
	    }while(try > 0);
	    free(p);
	    if(ret == &e_ok)
	    {
		    T_Package *q = (T_Package*)r->buf;
		    memcpy(next_hash, q->payload, TSU_HASH_LEN);
		    aqd_free(r);
	    }

	    return ret;
	}
	else
	{
	    return &e_no_mem;
	}

    return &e_result_invalid;
}

BoeErr* doTSU_GetNewHash(uint8_t *hash, uint8_t *next_hash, unsigned char *p_status)
{
	int wlen = 0;
	T_Package *p = make_query_get_new_hash(hash, &wlen);
	BoeErr *ret = NULL;
	AQData *r = NULL;
	int try = 3;
	
	if(p)
	{
	    do{
	        ret = doCommand(p, &r, gShortTimeout, wlen);
	        if(ret == &e_msgc_read_timeout)
	           try --;
	        else
	            break;
	    }while(try > 0);
	    free(p);
	    if(ret == &e_ok)
	    {
	    
		    T_Package *q = (T_Package*)r->buf;
		    *p_status = q->status;
		    memcpy(next_hash, q->payload, TSU_HASH_LEN);
		    aqd_free(r);
	    }

	    return ret;
	}
	else
	{
	    return &e_no_mem;
	}

    return &e_result_invalid;
}
BoeErr* doTSU_CheckHash(uint8_t *pre_hash, uint8_t *hash, unsigned char *p_result)
{
	int wlen = 0;
	T_Package *p = make_query_check_hash(pre_hash, hash, &wlen);
	BoeErr *ret = NULL;
	AQData *r = NULL;
	int try = 3;
	if(p)
	{
	    do{
	        ret = doCommand(p, &r, gShortTimeout, wlen);
	        if(ret == &e_msgc_read_timeout)
	           try --;
	        else
	            break;
	    }while(try > 0);
	    free(p);
	    if(ret == &e_ok)
	    {
		    T_Package *q = (T_Package*)r->buf;			
		    *p_result = q->status;
		    aqd_free(r);
	    }

	    return ret;
	}
	else
	{
	    return &e_no_mem;
	}

    return &e_result_invalid;
}
