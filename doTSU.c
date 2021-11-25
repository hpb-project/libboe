// Last Update:2020-11-01 17:50:34
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
    TSU_PreSendCallback presendCallback;
	void *userdata;
    RSContext  rs;
    MsgContext msgc;
}TSUContext;

static TSUContext gTsu;

#define TSU_RV (0xFF01)

#define TSU_PACKET_CONTROL (10)

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
            if(tsu_packet->status == RP_CHKSUM_ERROR)
            {
                // printf("boe--- response with error CHKSUM ERROR, package sequence = %d\n", tsu_packet->sequence);
                ctx->asyncCallback(type, NULL, m->d->len, m->userdata, m->userdata_len, tsu_packet_old->payload, ctx->userdata);
            }
            else
            {
                ctx->asyncCallback(type, tsu_packet->payload, m->d->len, m->userdata, m->userdata_len, tsu_packet_old->payload, ctx->userdata);    
            }		
		}
        
	}
    if (NULL != m)
    {
        WMessageFree(m);
    }
    
    return 0;
}

void doTSU_RegisAsyncCallback(AsyncCallback afun, void *data)
{
	TSUContext *ctx = &gTsu;
	ctx->asyncCallback = afun;
	ctx->userdata = data;
}

void doTSU_RegisPresendCallback(TSU_PreSendCallback pfun)
{
    TSUContext *ctx = &gTsu;
	ctx->presendCallback = pfun;
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
    msgc_set_packet_control(&(ctx->msgc), TSU_PACKET_CONTROL);
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
    T_Package *p = tsu_package_new(FUNCTION_ECSDA_CHECK, TX_SIG_LEN, 0);
    if(p)
    {
        tsu_set_data(p, 0, sig, TX_SIG_LEN);
        p->sub_function = checksum_byte(sig, TX_SIG_LEN);
        tsu_finish_package(p);
        *len = TX_SIG_LEN + sizeof(T_Package);
    }

    return p;
}

T_Package *make_query_get_hash(uint8_t *hash, int *len)
{
    T_Package *p = tsu_package_new(FUNCTION_GEN_HASH, TSU_HASH_LEN, 0);
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
    T_Package *p = tsu_package_new(FUNCTION_GEN_NEW_HASH, TSU_HASH_LEN, 0);
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
    T_Package *p = tsu_package_new(FUNCTION_GEN_NEW_HASH, TSU_HASH_CHECK_LEN, 1);
    if(p)
    {
    
        tsu_set_data(p, 0, pre_hash, TSU_HASH_LEN);
        tsu_set_data(p, TSU_HASH_LEN, hash, TSU_HASH_LEN);
        tsu_finish_package(p);
        *len = TSU_HASH_CHECK_LEN +sizeof(T_Package);
    }

    return p;
}
#define ZSC_BURN_MODE (0)
#define ZSC_TRANSFER_MODE (1)
#define BURNPROOF_LENGTH (2912)
#define TRANSFERPROOF_LENGTH (5088)
T_Multi_Package_List *make_query_zscVerify(uint8_t *data, uint8_t mode, uint32_t datalen, int *len)
{
    T_Multi_Package_List *list = tsu_zsc_proof_package_new(FUNCTION_ZSC_VERIFY, mode, data, datalen);
    return list;
}

static BoeErr* doCommand(T_Package *p, AQData **d, int timeout, int wlen)
{
    MsgContext *wqc = &gTsu.msgc;
    BoeErr *ret = BOE_OK;
    if(gTsu.presendCallback != NULL)
    {
        gTsu.presendCallback(p);
    }
    WMessage * wm = WMessageNew(p->sequence, tsu_check_response, timeout, (uint8_t*)p, wlen, 0);
    if(p->function_id == FUNCTION_ECSDA_CHECK || p->function_id == FUNCTION_ZSC_VERIFY)
    {
        WMessageWithPacketControl(wm, 1);
    }
    if(msgc_send_async(wqc, wm) == 0)
    {
        AQData *q = msgc_read(wqc, wm);
        if(q == NULL || q->buf == NULL)
        {
            ret = &e_msgc_read_timeout;
            goto end;
        }
        else
        {
            *d = q;
        }        
    }
    else
    {
        ret = &e_msgc_send_fail;
    }
end:
    if(wm != NULL)
    {
        WMessageFree(wm);
    }
    return ret;
}
#if 1
/*recover pub*/
static BoeErr* doCommandRecoverPubAsync(T_Package *p, int timeout, int wlen, unsigned char *param, int param_len)
{
    MsgContext *wqc = &gTsu.msgc;
    if(gTsu.presendCallback != NULL)
    {
        gTsu.presendCallback(p);
    }
    WMessage * wm = WMessageNew(p->sequence, tsu_check_response, timeout, (uint8_t*)p, wlen, 1);
    WMessageAddUserdata(wm, param, param_len);
    WMessageWithPacketControl(wm, 1);
	
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
            if(q->status == 0)
            {
                memcpy(pub, q->payload, TX_PUB_LEN);
            }
            else if(q->status == RP_CHKSUM_ERROR) 
            {
                ret = &e_checksum_error;
            }
            
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

BoeErr* doTSU_GetNewHash(uint8_t *hash, uint8_t *next_hash)
{
	int wlen = 0;
	T_Package *p = make_query_get_new_hash(hash, &wlen);
	BoeErr *ret = NULL;
	AQData *r = NULL;
	int try = 3;
	unsigned char p_status = 0;
		
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
		    p_status = q->status;
		    memcpy(next_hash, q->payload, TSU_HASH_LEN);
		    aqd_free(r);
	    }
	    if(0 == p_status)
	    {
	        return ret;
	    }
	    else if(RANDOM_TIME_LIMIT == p_status)
	    {
	        return &e_hash_get_time_limit;
	    }
	}
	else
	{
	    return &e_no_mem;
	}

    return &e_result_invalid;
}
BoeErr* doTSU_CheckHash(uint8_t *pre_hash, uint8_t *hash)
{
	int wlen = 0;
	T_Package *p = make_query_check_hash(pre_hash, hash, &wlen);
	BoeErr *ret = NULL;
	AQData *r = NULL;
	int try = 3;
	unsigned char p_result = 0;
		
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
		    p_result = q->status;
		    aqd_free(r);
	    }
	    if(1 == p_result)
	    {
	        return ret;
	    }
	    else if(0x11 == p_result)
	    {
	        return &e_hash_check_error;
	    }

	    return ret;
	}
	else
	{
	    return &e_no_mem;
	}

    return &e_result_invalid;
}

static BoeErr* doCommandAsync(T_Package *p, int timeout, int wlen, unsigned char *param, int param_len, int no_flow_control)
{
    MsgContext *wqc = &gTsu.msgc;
    WMessage * wm = WMessageNew(p->sequence, tsu_check_response, timeout, (uint8_t*)p, wlen, 1);
    WMessageAddUserdata(wm, param, param_len);
    if (no_flow_control != 1) 
    {
        WMessageWithPacketControl(wm, 1);
    }
	
    if(msgc_send_async(wqc, wm) == 0)
    {
        return &e_ok;
    }
    else
    {
        return &e_msgc_send_fail;
    }
}

BoeErr* doTSU_ZSCVerify(uint8_t *data, int len)
{
	int wlen = 0;
    uint8_t mode;
	T_Multi_Package_List *list = NULL, *p = NULL;
    T_Multi_Package_Node *node = NULL;
	BoeErr *ret = NULL;
	AQData *r = NULL;
	int retry = 3;
	uint8_t p_result = 0;

    if(len == BURNPROOF_LENGTH)
    {
        mode = ZSC_BURN_MODE;
    }
    else if (len == TRANSFERPROOF_LENGTH)
    {
        mode = ZSC_TRANSFER_MODE;
    }
    else 
    {
        ret = &e_param_invalid;
    }
    list = make_query_zscVerify(data, mode, len, &wlen);
    p = list;          
	if(p)
	{
        while(NULL != p->next)
        {
            node = p->next;
            if (NULL == node->next)
            {
                // the last one use sync command.
                //printf("send with async command, length = %d\n", node->package_len);
                ret = doCommand(node->package, &r, 1000, node->package_len);
                if (ret == &e_ok)
                {   // receive verify response.
                    T_Package *q = (T_Package*)r->buf;
                    if (q->status == RP_CHKSUM_ERROR)
                    {
                        ret = &e_checksum_error;
                        // resend max retry times.
                        if(retry > 0)
                        {
                            retry--;
                            p = list;
                            continue;
                        }
                    }
                    else
                    {
                        p_result = q->status; // got verify result.
                    }
                    
                    aqd_free(r);
                }
                break;
            }
            else
            {
                //printf("send with sync command, length = %d\n", node->package_len);
                ret = doCommandAsync(node->package, 100, node->package_len, NULL, 0, 1);
                if(ret != &e_ok)
                {
                    break;
                }
            }
            p = p->next;
        }
        tsu_zsc_proof_package_release(list);
	}
	else
	{
	    ret = &e_no_mem;
	}

    if(p_result == 0)
    {
        if (ret != &e_checksum_error)
        {
            // verify false.
            ret = &e_hw_verify_failed;
        }
    }
    else
    {   // verify true.
        ret = &e_ok;
    }

    return ret;
}

// ----- for test 
BoeErr* doTSU_ZSCVerify_out_of_order(uint8_t *data, int len)
{
	int wlen = 0;
    uint8_t mode;
	T_Multi_Package_List *list = NULL, *p = NULL;
    T_Multi_Package_Node *node = NULL;
	BoeErr *ret = NULL;
	AQData *r = NULL;
	int retry = 3;
	uint8_t p_result = 0;

    if(len == BURNPROOF_LENGTH)
    {
        mode = ZSC_BURN_MODE;
    }
    else if (len == TRANSFERPROOF_LENGTH)
    {
        mode = ZSC_TRANSFER_MODE;
    }
    else 
    {
        ret = &e_param_invalid;
    }
    list = make_query_zscVerify(data, mode, len, &wlen);
    p = list;          
    // out of the order.
    {
        T_Multi_Package_List *r1 = list->next;
        T_Multi_Package_List *r2 = r1->next;
        list->next = r2;
        r1->next = r2->next;
        r2->next = r1;
    }
	if(p)
	{
        while(NULL != p->next)
        {
            node = p->next;
            if (NULL == node->next)
            {
                // the last one use sync command.
                printf("send with async command, length = %d\n", node->package_len);
                ret = doCommand(node->package, &r, 1000, node->package_len);
                if (ret == &e_ok)
                {   // receive verify response.
                    T_Package *q = (T_Package*)r->buf;
                    if (q->status == RP_CHKSUM_ERROR)
                    {
                        ret = &e_checksum_error;
                        // resend max retry times.
                        if(retry > 0)
                        {
                            retry--;
                            p = list;
                            continue;
                        }
                    }
                    else
                    {
                        p_result = q->status; // got verify result.
                    }
                    
                    aqd_free(r);
                }
                break;
            }
            else
            {
                printf("send with sync command, length = %d\n", node->package_len);
                ret = doCommandAsync(node->package, 100, node->package_len, NULL, 0, 1);
                if(ret != &e_ok)
                {
                    break;
                }
            }
            p = p->next;
        }
        tsu_zsc_proof_package_release(list);
	}
	else
	{
	    ret = &e_no_mem;
	}

    if(p_result == 0)
    {
        if (ret != &e_checksum_error)
        {
            // verify false.
            ret = &e_hw_verify_failed;
        }
    }
    else
    {   // verify true.
        ret = &e_ok;
    }

    return ret;
}
# if 0
BoeErr* doTSU_ZSCVerify_Merge(uint8_t *data_1, int len_1, uint8_t *data_2, int len_2)
{
	int wlen = 0;
    uint8_t mode;
	T_Multi_Package_List *list = NULL, *p = NULL;
    T_Multi_Package_Node *node = NULL;
	BoeErr *ret = NULL;
	AQData *r = NULL;
	int retry = 3;
	uint8_t p_result = 0;

    if(len == BURNPROOF_LENGTH)
    {
        mode = ZSC_BURN_MODE;
    }
    else if (len == TRANSFERPROOF_LENGTH)
    {
        mode = ZSC_TRANSFER_MODE;
    }
    else 
    {
        ret = &e_param_invalid;
    }
    list = make_query_zscVerify(data, mode, len, &wlen);
    p = list;          
    // out of the order.
    {
        T_Multi_Package_List *r1 = list->next;
        T_Multi_Package_List *r2 = r1->next;
        list->next = r2;
        r1->next = r2->next;
        r2->next = r1;
    }
	if(p)
	{
        while(NULL != p->next)
        {
            node = p->next;
            if (NULL == node->next)
            {
                // the last one use sync command.
                printf("send with async command, length = %d\n", node->package_len);
                ret = doCommand(node->package, &r, 1000, node->package_len);
                if (ret == &e_ok)
                {   // receive verify response.
                    T_Package *q = (T_Package*)r->buf;
                    if (q->status == RP_CHKSUM_ERROR)
                    {
                        ret = &e_checksum_error;
                        // resend max retry times.
                        if(retry > 0)
                        {
                            retry--;
                            p = list;
                            continue;
                        }
                    }
                    else
                    {
                        p_result = q->status; // got verify result.
                    }
                    
                    aqd_free(r);
                }
                break;
            }
            else
            {
                printf("send with sync command, length = %d\n", node->package_len);
                ret = doCommandAsync(node->package, 100, node->package_len, NULL, 0, 1);
                if(ret != &e_ok)
                {
                    break;
                }
            }
            p = p->next;
        }
        tsu_zsc_proof_package_release(list);
	}
	else
	{
	    ret = &e_no_mem;
	}

    if(p_result == 0)
    {
        if (ret != &e_checksum_error)
        {
            // verify false.
            ret = &e_hw_verify_failed;
        }
    }
    else
    {   // verify true.
        ret = &e_ok;
    }

    return ret;
}
# endif