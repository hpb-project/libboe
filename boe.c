// Last Update:2018-08-08 11:40:27
/**
 * @file nboe.c
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-19
 */
#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>  
#include <arpa/inet.h>  
#include "sha3.h"
#include "genid.h"
#include "boe_full.h"
#include "sb_api.h"
#include "serror.h"
#include "common.h"
#include "doAXU.h"
#include "doTSU.h"

struct BoeInstance {
    TVersion hw;
    TVersion fw;
    TVersion axu;
    char     methname[100];
    uint8_t  bInitCon;
    uint8_t  bConnected;
    uint32_t updateFid;
    BoeUpgradeCallback updateCallback;
};

static struct BoeInstance gIns;

#define GetProgress(p)   (p->data[0])
#define GetProgressMsg(p) (p->data+1)
static int axu_msg_handle(uint8_t *data, int len, void *userdata)
{
    A_Package *p = (A_Package*)data;
    struct BoeInstance *ins = (struct BoeInstance*)userdata;
    if(p->header.magic_aacc == AXU_MAGIC_START &&
            p->header.magic_ccaa == AXU_MAGIC_END)
    {
        switch(p->header.acmd)
        {
            case ACMD_BP_RES_UPGRADE_PROGRESS:
                {
                    int progress = GetProgress(p);
                    char *msg    = (char*)GetProgressMsg(p);
                    if(ins->updateCallback != NULL)
                    {
                        ins->updateCallback(progress, msg);
                    }
                    break;
                }
            default:
                break;
        }
    }

    return 0;
}

static int tsu_msg_handle(uint8_t *data, int len, void *userdata)
{
    return 0;
}

static int connected(struct BoeInstance *ins)
{
    if(doAXU_GetVersionInfo(&ins->hw, &ins->fw, &ins->axu) == BOE_OK)
    {
        return 1;
    }else
    {
        return 0;
    }
}
void boe_err_free(BoeErr *e)
{
    if(e->bfree)
    {
        free(e);
    }
}

int find_eth(char *ethname)
{
    struct ifaddrs *ifa = NULL, *ifList;
    int find = 0;

    if (getifaddrs(&ifList) < 0)
    {
        return -1;
    }

    for (ifa = ifList; ifa != NULL; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr->sa_family == AF_INET)
        {
            char *name = ifa->ifa_name;
            if(strcmp(name, "lo") == 0)
                continue;
            if(doAXU_Init(name, axu_msg_handle, (void*)&gIns) == BOE_OK)
            {
                if(connected(&gIns))
                {
                    doAXU_Release();
                    memcpy(ethname, name, strlen(name));
                    ethname[strlen(name)+1] = '\0';
                    find = 1;
                    break;
                }
                else
                {
                    doAXU_Release();
                }
            }
            continue;
        }
    }

    freeifaddrs(ifList);
    return find;
}
BoeErr* boe_inner_init(char *ethname)
{
    BoeErr *ret = doAXU_Init(ethname, axu_msg_handle, (void*)&gIns);
    if(ret != BOE_OK)
    {
        return ret;
    }
    ret = doTSU_Init(ethname, tsu_msg_handle, (void*)&gIns);
    if(ret != BOE_OK)
    {
        doAXU_Release();
        return ret;
    }
    return ret;
}

BoeErr* init_check()
{
    BoeErr *ret = BOE_OK;
    if(gIns.bConnected)
        return BOE_OK;

    if(gIns.bInitCon != 1)
    {
        char ethname[30];
        if(!find_eth(ethname)) // find current ethname that connect with board.
        {
            return &e_init_fail;
        }
        strcpy(gIns.methname, ethname);

        ret = boe_inner_init(gIns.methname);
        if(ret == BOE_OK)
        {
            gIns.bInitCon = 1;
            if(connected(&gIns))
            {
                gIns.bConnected = 1;
            }
        }
    }
    else if(!gIns.bConnected)
    {
        if(connected(&gIns))
        {
            gIns.bConnected = 1;
        }
    }
    if(gIns.bConnected)
        return BOE_OK;

    return &e_init_fail;
}

BoeErr* boe_init(void)
{
    gIns.bInitCon = 0;
    gIns.bConnected = 0;
    memset(gIns.methname, 0x0, sizeof(gIns.methname));

    init_check();
    return BOE_OK;
}



BoeErr* boe_release(void)
{
    if(gIns.bInitCon)
    {
        doAXU_Release();
        doTSU_Release();
    }

    return BOE_OK;
}

BoeErr* boe_reg_update_callback(BoeUpgradeCallback func)
{
    gIns.updateCallback = func;
    return BOE_OK;
}

BoeErr* boe_get_all_version(TVersion *hw, TVersion *fw, TVersion *axu)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_GetVersionInfo(hw, fw, axu);
    return ret;
}

BoeErr* boe_get_hw_version(TVersion *hw)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_GetHWVer(hw);
    return ret;
}
BoeErr* boe_get_fw_version(TVersion *fw)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_GetFWVer(fw);
    return ret;
}
BoeErr* boe_get_axu_version(TVersion *axu)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_GetAXUVer(axu);
    return ret;
}

BoeErr* boe_upgrade(unsigned char*image, int imagelen)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
    {
        ImageHeader header;
        BoeErr* ret = NULL;
        memcpy(&header, image, sizeof(header));
        if((memcmp(header.vendor, "hpb", 3) == 0)
                && (imagelen - sizeof(header) == header.len))
        {
            uint8_t *p_data = image + sizeof(ImageHeader);
            uint32_t chk = checksum(p_data, header.len);
            if(chk != header.chk)
            {
                printf("boe_upgrade: checksum not match\n");
                return &e_image_chk_error;
            }
            gIns.updateFid = header.chk;

            ret = doAXU_Transport(&header, p_data);
            if(ret != BOE_OK)
                return ret;
            ret = doAXU_UpgradeStart(gIns.updateFid);
        }
        else
        {
            return &e_image_header_error;
        }
    }
    return ret;
}

BoeErr* boe_upgrade_abort(void)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_UpgradeAbort(gIns.updateFid);
    return ret;
}
BoeErr* boe_hw_check(void)
{
    TVersion hw, fw, axuver;
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_GetVersionInfo(&hw, &fw, &axuver);
    return ret;
}
BoeErr* boe_reboot(void)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_Reset();
    return ret;
}
BoeErr* boe_set_boesn(unsigned char *sn)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_SetBoeSN(sn);
    return ret;
}
BoeErr* boe_set_bind_account(unsigned char *account)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_BindAccount(account);
    return ret;
}

BoeErr* boe_get_random(unsigned char *r)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_GetRandom(r);
    return ret;
}
BoeErr* boe_get_boesn(unsigned char *sn)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_GetBOESN(sn);
    return ret;
}
BoeErr* boe_get_bind_account(unsigned char *baccount)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_GetBindAccount(baccount);
    return ret;
}

BoeErr* boe_hw_sign(unsigned char *p_random, unsigned char *sig)
{
    // merge p_random and hid, 
    // sha3_256 generate hash.
    // use hash to signature.
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
    {
        int len = 32 + 2 * 32;
        unsigned char p_buf[32 + 2*32];
        memset(p_buf, 0, len);
        if(0 == general_id(p_buf))
        {
            uint8_t hash[32] = {0};
            memcpy(p_buf+2*32, p_random, 32);
            SHA3_256(hash, p_buf, len);
            return doAXU_HWSign(hash, sig);
        }
        return &e_gen_host_id_failed;
    }
    return ret;
}
BoeErr* boe_p256_verify(unsigned char *random, unsigned char *signature, unsigned char * hid, unsigned char *pubkey)
{
    int len = 32 + 2 * 32;
    unsigned char p_buf[32 + 2*32];
    memset(p_buf, 0, len);
    memcpy(p_buf, hid, 32 * 2);
    memcpy(p_buf+2*32, random, 32);

    uint8_t hash[32] = {0};
    SHA3_256(hash, p_buf, len);

    int ret = p256_verify(hash, pubkey, signature);
    if(ret == 0)
        return BOE_OK;
    return &e_hw_verify_failed;
}
BoeErr* boe_genkey(unsigned char *pubkey)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_Genkey(pubkey);
    return ret;
}
BoeErr* boe_get_pubkey(unsigned char *pubkey)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_Get_Pubkey(pubkey);
    return ret;
}
BoeErr* boe_lock_pk(void)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_Lock_PK();
    return ret;
}
BoeErr* boe_hw_verify(unsigned char *hash, unsigned char *signature, unsigned char *pubkey)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_HW_Verify(hash, signature, pubkey);
    return ret;
}
BoeErr* boe_set_mac(unsigned char *mac)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_Set_MAC(mac);
    return ret;
}
BoeErr* boe_get_mac(unsigned char *mac)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doAXU_Get_MAC(mac);
    return ret;
}
/* -------------------  tsu command -------------------------*/
BoeErr* boe_get_s_random(unsigned char *hash, unsigned char *nexthash)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doTSU_GetHash(hash, nexthash);
    return ret;
}
BoeErr* boe_valid_sign(unsigned char *sig, unsigned char *pub)
{
    BoeErr *ret = init_check();
    if(ret == BOE_OK)
        return doTSU_RecoverPub(sig, pub);
    return ret;
}
