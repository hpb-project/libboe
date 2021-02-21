#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "common.h"
#include "msgc.h"
#include "axu_connector.h"
#include "rs.h"
#include "serror.h"
#include "doAXU.h"
#include <pthread.h>
#include <unistd.h>


typedef struct AXUContext {
    RSContext  rs;
    MsgContext wqc;
}AXUContext;

static int gShortTimeout = 1000; // 1s
static AXUContext gAxu;
#define AXU_TYPE (0xff00)
#define ACCOUNT_LEN  (42)
#define BOARD_SN_LEN (20)
#define HWSIGN_LEN   (64)
#define PUBKEY_LEN   (64)
#define BOARD_MAC_LEN (6)
#define RANDOM_LEN   (32)
#define HASH_LEN     (32)

#define PSetData(p, o, v) \
    {\
        axu_set_data(p, o, (uint8_t*)&(v), sizeof(v));\
        o += sizeof(v);\
    }

#define PSetDataLen(p, o, v, l) \
    {\
        axu_set_data(p, o, (uint8_t*)(v), l);\
        o += l;\
    }

#define MajorHVer(hv) ((hv)&0xf0>>4)
static int axu_check_response(uint8_t* data, int plen, uint32_t uid);

static inline int isAck(A_Package *p)
{
    return p->header.acmd == ACMD_BP_RES_ACK;
}
static inline int isErr(A_Package *p)
{
    return p->header.acmd == ACMD_BP_RES_ERR;
}

static BoeErr* get_error(A_Package *p)
{
    int ecode = p->data[0];
    BoeErr *ret = NULL;
    if(ecode < MAX_AXU_ERRNUM)
    {
        ret = &e_axu_inner[ecode];
        ret->bfree = 0;
    }
    else
    {
        ret = (BoeErr*)malloc(sizeof(BoeErr));
        ret->bfree = 1;
    }
    ret->ecode = p->data[0];
    strncpy(ret->emsg, (char*)(p->data+1), sizeof(ret->emsg)-1);
    return ret;
}

static BoeErr* doCommandWithTimeout(A_Package *p, AQData **d, uint64_t timeout_ms)
{
    BoeErr *ret = NULL;
    MsgContext *wqc = &gAxu.wqc;
    WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, timeout_ms, (uint8_t*)p,
            axu_package_len(p), 0);
    if(wm == NULL)
    {
        ret = &e_no_mem;
        goto end;
    }
    if(msgc_send_async(wqc, wm) == 0)
    {
        AQData *q = msgc_read(wqc, wm);
        if(q == NULL || q->buf == NULL)
        {
            ret = &e_msgc_read_timeout;
            goto end;
        }

        A_Package *r = (A_Package*)q->buf;
        if(isErr(r))
        {
            ret = get_error(r);
            aqd_free(q);
            goto end;
        }
        else
        {
            *d = q;
            ret = &e_ok;
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

static BoeErr* doCommand(A_Package *p, AQData **d)
{
    BoeErr *ret = NULL;
    MsgContext *wqc = &gAxu.wqc;
    WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout, (uint8_t*)p,
            axu_package_len(p), 0);
    if(wm == NULL)
    {
        ret = &e_no_mem;
        goto end;
    }
    if(msgc_send_async(wqc, wm) == 0)
    {
        AQData *q = msgc_read(wqc, wm);
        if(q == NULL || q->buf == NULL)
        {
            ret = &e_msgc_read_timeout;
            goto end;
        }

        A_Package *r = (A_Package*)q->buf;
        if(isErr(r))
        {
            ret = get_error(r);
            aqd_free(q);
            goto end;
        }
        else
        {
            *d = q;
            ret = &e_ok;
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

static A_Package* make_query_simple(ACmd cmd)
{
    A_Package *p = axu_package_new(0);
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_ts_start(ACmd cmd, uint8_t usage, uint32_t fid, uint32_t chk,
        uint32_t len, TVersion v)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, usage);
        PSetData(p, offset, fid);
        PSetData(p, offset, chk);
        PSetData(p, offset, len);
        PSetData(p, offset, v.H);
        PSetData(p, offset, v.M);
        PSetData(p, offset, v.F);
        PSetData(p, offset, v.D);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_ts_mid(ACmd cmd, uint32_t fid, uint32_t doffset, uint32_t len, uint8_t *data)
{
    int offset = 0;
    A_Package *p = axu_package_new(PACKAGE_MAX_SIZE);

    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, fid);
        PSetData(p, offset, doffset);
        PSetData(p, offset, len);
        PSetDataLen(p, offset, data, len);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_ts_fin(ACmd cmd, uint32_t fid, uint32_t doffset, uint32_t len, uint8_t *data)
{
    A_Package *p = axu_package_new(PACKAGE_MAX_SIZE);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, fid);
        PSetData(p, offset, doffset);
        PSetData(p, offset, len);
        PSetDataLen(p, offset, data, len);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_upgrade_start(ACmd cmd, uint32_t fid)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, fid);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_upgrade_abort(ACmd cmd, uint32_t fid)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetData(p, offset, fid);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_set_boesn(ACmd cmd, unsigned char *sn)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, sn, BOARD_SN_LEN);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_verify(ACmd cmd, unsigned char *hash, unsigned char *signature, unsigned char *pubkey)
{
    A_Package *p = axu_package_new(HWSIGN_LEN + PUBKEY_LEN + HASH_LEN);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, hash, HASH_LEN);
        PSetDataLen(p, offset, signature, HWSIGN_LEN);
        PSetDataLen(p, offset, pubkey, PUBKEY_LEN);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_set_boe_mac(ACmd cmd, unsigned char *mac)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, mac, BOARD_MAC_LEN);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_phy_reg(ACmd cmd, uint32_t reg)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, (uint8_t*)&reg, sizeof(reg));

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_write_reg(ACmd cmd, uint32_t reg, uint32_t val)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, (uint8_t*)&reg, sizeof(reg));
        PSetDataLen(p, offset, (uint8_t*)&val, sizeof(val));

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_read_reg(ACmd cmd, uint32_t reg)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, (uint8_t*)&reg, sizeof(reg));

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_phy_shd_reg(ACmd cmd, uint32_t reg, uint16_t shd)
{
    A_Package *p = axu_package_new(100);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, (uint8_t*)&reg, sizeof(reg));
        PSetDataLen(p, offset, (uint8_t*)&shd, sizeof(shd));

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_bind_account(ACmd cmd, uint8_t *baccount)
{
    A_Package *p = axu_package_new(ACCOUNT_LEN);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, baccount, ACCOUNT_LEN);

        axu_finish_package(p);
    }
    return p;
}

static A_Package* make_query_hwsign(ACmd cmd, uint8_t *data, uint32_t len)
{
    A_Package *p = axu_package_new(len);
    int offset = 0;
    if(p)
    {
        axu_package_init(p, NULL, cmd);
        PSetDataLen(p, offset, data, len);

        axu_finish_package(p);
    }
    return p;
}

int axu_check_response(uint8_t* data, int plen, uint32_t uid)
{
    if(plen >= sizeof(A_Package))
    {
        A_Package *p = (A_Package*)data;
        if(p->header.magic_aacc == AXU_MAGIC_START &&
                p->header.magic_ccaa == AXU_MAGIC_END)
        {
            if(p->header.package_id == uid && p->header.q_or_r == AP_RESPONSE)
                return 1;
        }
    }
    return 0;
}



#define BPGetHVersion(p)  (p->data[0])
#define BPGetMVersion(p)  (p->data[1])
#define BPGetFVersion(p)  (p->data[2])
#define BPGetDVersion(p)  (p->data[3])
BoeErr* doAXU_GetVersionInfo(unsigned char *H, unsigned char *M, unsigned char *F, unsigned char *D)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_VERSION_INFO);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    int try = 3;
	
    if(p)
    {
        do{
            ret = doCommandWithTimeout(p, &r,200);
            if(ret == &e_msgc_read_timeout)
                try--;
            else
                break;
        }while(try > 0);
        free(p);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);

            *H = MajorHVer(BPGetHVersion(q));
            *M = BPGetMVersion(q);
            *F = BPGetFVersion(q);
            *D = BPGetDVersion(q);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}


BoeErr* doAXU_Reset(void)
{
    A_Package *p = make_query_simple(ACMD_PB_RESET);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}


BoeErr* doAXU_GetRandom(unsigned char *rdm)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_RANDOM);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    int i = 0;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            memcpy(rdm, q->data, RANDOM_LEN);
            aqd_free(r);
            return &e_ok;
        }
    }

    srandom(time(NULL));
    for(i = 0; i < 8; i++)
    {
        uint32_t rm = random();
        memcpy(rdm+4*i, &rm, sizeof(rm));
    }
    return &e_ok;
}

BoeErr* doAXU_GetBOESN(unsigned char *sn)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_SN);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            memcpy(sn, q->data, BOARD_SN_LEN);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Get_MAC(unsigned char *mac)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_MAC);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        int try = 3;
        do{
            ret = doCommand(p, &r);
            if(ret != &e_ok)
                try--;
            else
                break;
        }while(try > 0);

        free(p);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            memcpy(mac, q->data, BOARD_MAC_LEN);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Genkey(unsigned char *pubkey)
{
    A_Package *p = make_query_simple(ACMD_PB_GENKEY);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            memcpy(pubkey, q->data, PUBKEY_LEN);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Get_Pubkey(unsigned char *pubkey)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_PUBKEY);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        int try = 3;
        do{
            ret = doCommand(p, &r);
            if(ret != &e_ok)
                try--;
            else
                break;
        }while(try > 0);
        free(p);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            memcpy(pubkey, q->data, PUBKEY_LEN);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_HW_Verify(unsigned char *hash, unsigned char *signature, unsigned char *pubkey)
{
    A_Package *p = make_query_verify(ACMD_PB_VERIFY, hash, signature, pubkey);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        int try = 3;
        do{
            ret = doCommand(p, &r);
            if(ret != &e_ok)
                try--;
            else
                break;
        }while(try > 0);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Lock_PK()
{
    A_Package *p = make_query_simple(ACMD_PB_LOCK_PRIKEY);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}


BoeErr* doAXU_GetBindAccount(uint8_t *account)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_ACCOUNT);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        int try = 3;
        do{
            ret = doCommand(p, &r);
            if(ret != &e_ok)
                try--;
            else
                break;
        }while(try > 0);

        free(p);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            memcpy(account, q->data, ACCOUNT_LEN);
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_SetBoeSN(unsigned char *sn)
{
    A_Package *p = make_query_set_boesn(ACMD_PB_SET_SN, sn);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}
BoeErr* doAXU_Set_MAC(unsigned char *mac)
{
    A_Package *p = make_query_set_boe_mac(ACMD_PB_SET_MAC, mac);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Phy_Read(uint32_t reg, uint16_t *val)
{
    A_Package *p = make_query_phy_reg(ACMD_PB_PHY_READ, reg);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);

        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)r->buf;
            *val = *(uint16_t*)(q->data);
            aqd_free(r);

            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Phy_Shd_Read(uint32_t reg, uint16_t shadow, uint16_t *val)
{
    A_Package *p = make_query_phy_shd_reg(ACMD_PB_PHY_SHD_READ, reg, shadow);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);

        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)r->buf;
            *val = *(uint16_t*)(q->data);
            aqd_free(r);

            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Reg_Write(uint32_t reg, uint32_t val)
{
    A_Package *p = make_query_write_reg(ACMD_PB_REG_WRITE, reg, val);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);

        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Reg_Read(uint32_t reg, uint32_t *val)
{
    A_Package *p = make_query_read_reg(ACMD_PB_REG_READ, reg);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);

        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)r->buf;
            *val = *(uint32_t*)(q->data);
            aqd_free(r);

            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

int g_random_flag = 0;
unsigned char g_random_num[32] = {0};
void *doAXU_Reg_Random_Read_Thread()
{	
    unsigned char random_temp[32];

    while(g_random_flag == 1)
    {
        memset(random_temp, 0, sizeof(random_temp));
        BoeErr *ret = doAXU_Reg_Random_Read(random_temp);
        if(ret != &e_ok)
        {
            // printf("doAXU_Reg_Random_Read error %d\n",ret->ecode);
        }
        else
        {			
            memcpy(g_random_num,random_temp,sizeof(g_random_num));
        }
        sleep(1);
    }
    return NULL;
}

BoeErr* doAXU_Reg_Random_Read(unsigned char *val)
{
    A_Package *p = make_query_simple(ACMD_PB_REG_RANDOM);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);

        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)r->buf;
            memcpy(val,q->data,32);
            aqd_free(r);

            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}


BoeErr* doAXU_BindAccount(uint8_t *baccount)
{
    A_Package *p = make_query_bind_account(ACMD_PB_BIND_ACCOUNT, baccount);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        int try = 3;
        do{
            ret = doCommand(p, &r);
            if(ret != &e_ok)
                try--;
            else
                break;
        }while(try > 0);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_HWSign(uint8_t *data, uint8_t *result)
{
    A_Package *p = make_query_hwsign(ACMD_PB_HW_SIGN, data, HASH_LEN);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        int try = 3;
        do{
            ret = doCommand(p, &r);
            if(ret != &e_ok)
                try--;
            else
                break;
        }while(try > 0);

        free(p);
        if(ret == &e_ok)
        {
            // get sign r, s.
            A_Package *q = (A_Package*)r->buf;
            if(q->header.body_length >= HWSIGN_LEN)
            {
                memcpy(result, q->data, HWSIGN_LEN);
                aqd_free(r);
                return &e_ok;
            }
            else
            {
                aqd_free(r);
                return &e_result_invalid;
            }
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_TransportStart(ImageHeader *info)
{
    A_Package *p = make_query_ts_start(ACMD_PB_TRANSPORT_START, info->usage, 
            info->chk, info->chk, info->len, info->version);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

#define TransMidFidOffset()     (0)
#define TransMidOffsetOffset()  (4)
#define TransMidLenOffset()     (8)
#define TransMidDataOffset()    (12)
BoeErr* doAXU_TransportMid(uint32_t fid, uint32_t offset, int len, uint8_t *data)
{
    A_Package *p = make_query_ts_mid(ACMD_PB_TRANSPORT_MIDDLE, fid, offset, len, data);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommandWithTimeout(p, &r, 1500);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_TransportFin(uint32_t fid, uint32_t offset, int len, uint8_t *data)
{
    A_Package *p = make_query_ts_fin(ACMD_PB_TRANSPORT_FINISH, fid, offset, len, data);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

BoeErr* doAXU_Transport(ImageHeader *info, uint8_t *data)
{
    BoeErr *ret = NULL;
    ret = doAXU_TransportStart(info);

    if(ret == BOE_OK)
    {
        uint32_t offset = 0;
        int plen = 0;
        int pmaxlen = PACKAGE_MAX_SIZE - TransMidDataOffset();
        //PROFILE_START();
        while(1)
        {
            plen = info->len - offset;
            //printf("offset = %d.\n", offset);

            if(plen > pmaxlen)
            {
                ret = doAXU_TransportMid(info->chk, offset, pmaxlen, data+offset);
                //printf("transport mid data len %d\n", pmaxlen);
                offset += pmaxlen;
                if(ret != &e_ok)
                    break;
            }
            else
            {
                ret = doAXU_TransportFin(info->chk, offset, plen, data+offset);
                //printf("transport fin data len %d\n", plen);
                offset += plen;
                break;
            }
        }
        //PROFILE_END();
        return ret;
    }
    return ret;
}

BoeErr* doAXU_UpgradeStart(uint32_t fid)
{
    A_Package *p = make_query_upgrade_start(ACMD_PB_UPGRADE_START, fid);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommandWithTimeout(p, &r, 120*1000); // 2mins
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}


BoeErr* doAXU_UpgradeAbort(uint32_t fid)
{
    A_Package *p = make_query_upgrade_abort(ACMD_PB_UPGRADE_ABORT, fid);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            aqd_free(r);
            return &e_ok;
        }
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
}

static int asu_msg_callback(WMessage *m, void*userdata)
{
    // printf("axu rcv \n");
    return 0;
}


BoeErr* doAXU_Init(char *ethname, MsgHandle msghandle, void*userdata)
{
    int ret = 0;

    ret = RSCreate(ethname, AXU_TYPE, &(gAxu.rs));
    if(ret != 0)
    {
        return &e_init_fail;
    }
    ret = msgc_init(&gAxu.wqc, &gAxu.rs, msghandle, userdata, asu_msg_callback);
    if(ret != 0)
    {
        RSRelease(&gAxu.rs);
        return &e_init_fail;
    }
    return &e_ok;
}

BoeErr* doAXU_Release()
{
    RSRelease(&gAxu.rs);
    msgc_release(&gAxu.wqc);
    return &e_ok;
}

pthread_t random_thread;
void *random_thread_create(void)
{
    int ret = 0;
    TVersion version;
	
    doAXU_GetVersionInfo(&version.H, &version.M, &version.F, &version.D);
    if(version.F >= 1)
    {
        g_random_flag = 1;
    }
    else
    {
        g_random_flag = 2;
        printf("BOE version is low cannot start true_random function\n");
        return NULL;
    }

    ret = pthread_create(&random_thread, NULL, doAXU_Reg_Random_Read_Thread, NULL);
    if(0 != ret)
    {
        printf("pthread_create random_thread error\n");
    }

    return NULL;
}
void *random_thread_release(void)
{
    int ret = 0;
	
    if(2 == g_random_flag)
    {
        return NULL;
    }
	
    g_random_flag = 0;
    ret = pthread_join(random_thread, NULL);
    if(0 != ret)
    {
        printf("pthread_join random_thread error\n");
    }
    return NULL;
}

