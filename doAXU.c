#include <string.h>
#include <stdio.h>
#include "common.h"
#include "msgc.h"
#include "axu_connector.h"
#include "rs.h"
#include "serror.h"
#include "doAXU.h"

static struct timeval gTs, gTe;
static struct timezone gTz;

#define PROFILE_START() \
    gettimeofday(&gTs, &gTz);\

#define PROFILE_END() \
    gettimeofday(&gTe, &gTz);\
    printf("--PROFILE-- cost time %ldms.\n", (gTe.tv_sec*1000000 + gTe.tv_usec - gTs.tv_sec*1000000 - gTs.tv_usec)/1000);

typedef struct AXUContext {
    RSContext  rs;
    MsgContext wqc;
}AXUContext;

static int gShortTimeout = 1000000; // 1s
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
static BoeErr* doCommand(A_Package *p, AQData **d)
{
    BoeErr *ret = NULL;
    MsgContext *wqc = &gAxu.wqc;
    WMessage * wm = WMessageNew(p->header.package_id, axu_check_response, gShortTimeout, (uint8_t*)p,
            axu_package_len(p));
    if(wm == NULL)
    {
        ret = &e_no_mem;
        goto end;
    }
    if(msgc_send(wqc, wm) == 0)
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
        uint32_t len, TVersion hw, TVersion fw, TVersion axu)
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
        PSetData(p, offset, hw);
        PSetData(p, offset, fw);
        PSetData(p, offset, axu);

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



#define BPGetHWVersion(p)  (p->data[0])
#define BPGetFWVersion(p)  (p->data[1])
#define BPGetAXUVersion(p)  (p->data[2])
BoeErr* doAXU_GetVersionInfo(TVersion *hw, TVersion *fw, TVersion *axu)
{
    A_Package *p = make_query_simple(ACMD_PB_GET_VERSION_INFO);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);

            *hw = BPGetHWVersion(q);
            *fw = BPGetFWVersion(q);
            *axu = BPGetAXUVersion(q);
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
        return ret;
    }
    else
    {
        return &e_no_mem;
    }
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
        ret = doCommand(p, &r);
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

BoeErr* doAXU_HW_Verify(unsigned char *hash, unsigned char *signature, unsigned char *pubkey)
{
    A_Package *p = make_query_verify(ACMD_PB_VERIFY, hash, signature, pubkey);
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

BoeErr* doAXU_Lock_PK()
{
    A_Package *p = make_query_simple(ACMD_PB_GET_PUBKEY);
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

BoeErr* doAXU_GetSingleVer(TVersion *v, ACmd cmd)
{
    A_Package *p = make_query_simple(cmd);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
        free(p);
        if(ret == &e_ok)
        {
            A_Package *q = (A_Package*)(r->buf);
            *v = (*((TVersion*)(q->data)));
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
        ret = doCommand(p, &r);
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
BoeErr* doAXU_GetHWVer(TVersion *hw)
{
    return doAXU_GetSingleVer(hw, ACMD_PB_GET_HW_VER);
}

BoeErr* doAXU_GetFWVer(TVersion *fw)
{
    return doAXU_GetSingleVer(fw, ACMD_PB_GET_FW_VER);
}

BoeErr* doAXU_GetAXUVer(TVersion *axu)
{
    return doAXU_GetSingleVer(axu, ACMD_PB_GET_AXU_VER);
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

BoeErr* doAXU_BindAccount(uint8_t *baccount)
{
    A_Package *p = make_query_bind_account(ACMD_PB_BIND_ACCOUNT, baccount);
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

BoeErr* doAXU_HWSign(uint8_t *data, uint8_t *result)
{
    A_Package *p = make_query_hwsign(ACMD_PB_HW_SIGN, data, HASH_LEN);
    BoeErr *ret = NULL;
    AQData *r = NULL;
    if(p)
    {
        ret = doCommand(p, &r);
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
            info->chk, info->chk, info->len, info->hw, info->fw, info->axu);
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
        PROFILE_START();
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
                printf("transport fin data len %d\n", plen);
                offset += plen;
                break;
            }
        }
        PROFILE_END();
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


BoeErr* doAXU_Init(char *ethname, MsgHandle msghandle, void*userdata)
{
    int ret = 0;

    ret = RSCreate(ethname, AXU_TYPE, &(gAxu.rs));
    if(ret != 0)
    {
        return &e_init_fail;
    }
    ret = msgc_init(&gAxu.wqc, &gAxu.rs, msghandle, userdata);
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
