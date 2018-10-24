// Last Update:2018-08-21 16:25:40
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
#include <unistd.h>
#include "genid.h"
#include "boe_full.h"
#include "sb_api.h"
#include "serror.h"
#include "common.h"
#include "doAXU.h"
#include "doTSU.h"

struct BoeInstance {
    TVersion version;
    char     methname[100];
    uint8_t  bInitCon;
    uint8_t  bConnected;
    uint32_t updateFid;
    BoeUpgradeCallback updateCallback;
    BoeValidSignCallback validsignCallback;
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

static int async_tsu_callback(int type, unsigned char * response, unsigned int pid, unsigned char * source, void * userdata)
{
    struct BoeInstance *ins = (struct BoeInstance*)userdata;
	if(type == FUNCTION_ECSDA_CHECK && ins->validsignCallback != NULL)
	{
		ins->validsignCallback(response, source, (void*)&pid);
	}

    return 0;
}

static int connected(struct BoeInstance *ins)
{
    if(doAXU_GetVersionInfo(&ins->version.H, &ins->version.M, &ins->version.F, &ins->version.D) == BOE_OK)
    {
        return 1;
    }else
    {
        return 0;
    }
}
static BoeErr * bConnected()
{
    if(gIns.bInitCon && gIns.bConnected)
    {
        return BOE_OK;
    }
    return &e_init_fail;
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
        char *name = ifa->ifa_name;
        if(strcmp(name, "lo") == 0)
            continue;
        if(doAXU_Init(name, axu_msg_handle, (void*)&gIns) == BOE_OK)
        {
            if(connected(&gIns))
            {
                doAXU_Release();
                strcpy(ethname, name);
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
	doTSU_RegisAsyncCallback(async_tsu_callback, (void *)&gIns);
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
        if(!find_eth(gIns.methname)) // find current ethname that connect with board.
        {
            return &e_init_fail;
        }

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

int test_eth(char *ethname)
{
    if(doAXU_Init(ethname, axu_msg_handle, (void*)&gIns) == BOE_OK)
    {
        if(connected(&gIns))
        {
            doAXU_Release();
            return 0;
        }
        else
        {
            doAXU_Release();
        }
    }
    return 1;
}

BoeErr* test_init()
{
    BoeErr *ret = BOE_OK;
    if(gIns.bConnected)
        return BOE_OK;

    if(gIns.bInitCon != 1)
    {
        if(0!=test_eth(gIns.methname)) // find current ethname that connect with board.
        {
            return &e_init_fail;
        }

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
    return init_check();
}


BoeErr* boe_test_init(char *ethname)
{
    gIns.bInitCon = 0;
    gIns.bConnected = 0;
    strcpy(gIns.methname, ethname);
    return test_init();
}

BoeErr* boe_release(void)
{
    if(gIns.bInitCon)
    {
        doAXU_Release();
        doTSU_Release();
    }
    gIns.bInitCon = 0;

    return BOE_OK;
}

BoeErr* boe_reg_update_callback(BoeUpgradeCallback func)
{
    gIns.updateCallback = func;
    return BOE_OK;
}

BoeErr* boe_get_version(unsigned char *H, unsigned char *M, unsigned char *F, unsigned char *D)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_GetVersionInfo(H,M,F,D);
    return ret;
}

BoeErr* boe_get_hw_version(unsigned char *H)
{
    if(gIns.bConnected)
    {
        *H = gIns.version.H;
        return BOE_OK;
    }
    return &e_init_fail;

}
BoeErr* boe_get_m_version(unsigned char *M)
{
    if(gIns.bConnected)
    {
        *M = gIns.version.M;
        return BOE_OK;
    }
    return &e_conn_fail;
}

BoeErr* boe_upgrade(unsigned char*image, int imagelen)
{
    BoeErr *ret = bConnected();
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
            if(ret != BOE_OK)
            {
                return ret;
            }
            else 
            {
                // wait board reboot
                TVersion version;
                int waittime = 10;
                while(waittime > 0){
                    if(BOE_OK == doAXU_GetVersionInfo(&version.H,&version.M,&version.F,&version.D))
                    {
                        if(version.H==header.version.H && version.M == header.version.M 
                            && version.F==header.version.F && version.D == header.version.D)
                        {
                            printf("upgrade successed\r\n");
                            return BOE_OK;
                        }
                        else
                        {
                            printf("version not update, upgrade failed\r\n");
                            return &e_update_ver_not_match;
                        }
                    }
                    usleep(500000);
                    waittime--;
                }
                return &e_update_reboot_failed;
            }
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
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_UpgradeAbort(gIns.updateFid);
    return ret;
}
BoeErr* boe_hw_check(void)
{
    TVersion version;
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_GetVersionInfo(&version.H, &version.M, &version.F, &version.D);
    return ret;
}
BoeErr* boe_hw_connect(void)
{
    return bConnected();
}
BoeErr* boe_reboot(void)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_Reset();
    return ret;
}
BoeErr* boe_set_boesn(unsigned char *sn)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_SetBoeSN(sn);
    return ret;
}
BoeErr* boe_set_bind_account(unsigned char *account)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_BindAccount(account);
    return ret;
}

BoeErr* boe_get_random(unsigned char *r)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_GetRandom(r);
    return ret;
}
BoeErr* boe_get_boesn(unsigned char *sn)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_GetBOESN(sn);
    return ret;
}
BoeErr* boe_get_bind_account(unsigned char *baccount)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_GetBindAccount(baccount);
    return ret;
}

static void hex_dump_ln(unsigned char *buf, int len)
{
    for(int i =0; i < len; i++)
    {
        printf("%02x", buf[i]);
    }
    printf("\n");

}

BoeErr* boe_hw_sign(unsigned char *p_random, unsigned char *sig)
{
    // merge p_random and hid, 
    // sha3_256 generate hash.
    // use hash to signature.
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
    {
        int len = 32 + 32;
        unsigned char p_buf[32 + 32];
        memset(p_buf, 0, len);
        if(0 == general_id(p_buf))
        {
            // hid(32)+random(32)
            uint8_t hash[32] = {0};
            memcpy(p_buf+32, p_random, 32);
            //printf("boe hwsign---p_buf:0x");
            //hex_dump_ln(p_buf, sizeof(p_buf));
            SHA3_256(hash, p_buf, len);
            //printf("boe hwsign---hash:0x");
            //hex_dump_ln(hash, sizeof(hash));
            return doAXU_HWSign(hash, sig);
        }
        return &e_gen_host_id_failed;
    }
    return ret;
}
BoeErr* boe_p256_verify(unsigned char *random,  unsigned char * hid, unsigned char *pubkey, unsigned char *signature)
{
    int len = 32 + 32;
    unsigned char p_buf[32 + 32];
    memset(p_buf, 0, len);
    memcpy(p_buf, hid, 32);
    memcpy(p_buf+32, random, 32);

    //printf("boe verify---p_buf:0x");
    //hex_dump_ln(p_buf, sizeof(p_buf));
    uint8_t hash[32] = {0};
    SHA3_256(hash, p_buf, len);
    //printf("boe verify---hash:0x");
    //hex_dump_ln(hash, sizeof(hash));

    int ret = p256_verify(hash, pubkey, signature);
    if(ret == 0)
        return BOE_OK;
    return &e_hw_verify_failed;
}
BoeErr* boe_genkey(unsigned char *pubkey)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_Genkey(pubkey);
    return ret;
}
BoeErr* boe_get_pubkey(unsigned char *pubkey)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_Get_Pubkey(pubkey);
    return ret;
}
BoeErr* boe_lock_pk(void)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_Lock_PK();
    return ret;
}
BoeErr* boe_hw_verify(unsigned char *hash, unsigned char *signature, unsigned char *pubkey)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_HW_Verify(hash, signature, pubkey);
    return ret;
}
BoeErr* boe_set_mac(unsigned char *mac)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_Set_MAC(mac);
    return ret;
}
BoeErr* boe_get_mac(unsigned char *mac)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doAXU_Get_MAC(mac);
    return ret;
}
BoeErr* boe_phy_read(unsigned int reg, unsigned int *val)
{
    BoeErr *ret = bConnected();
    uint16_t sval = 0;
    if(ret == BOE_OK)
    {
        ret = doAXU_Phy_Read(reg, &sval);
        if(ret == BOE_OK)
        {
            *val = sval;
        }
    }

    return ret;
}
BoeErr* boe_phy_shd_read(unsigned int reg, unsigned int shd, unsigned int *val)
{
    BoeErr *ret = bConnected();
    uint16_t sval = 0;
    uint16_t sshd = shd;
    if(ret == BOE_OK)
    {
        ret = doAXU_Phy_Shd_Read(reg, sshd, &sval);
        if(ret == BOE_OK)
        {
            *val = sval;
        }
    }

    return ret;
}
BoeErr* boe_reg_read(unsigned int reg, unsigned int *val)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
    {
        ret = doAXU_Reg_Read(reg, val);
    }

    return ret;
}
BoeErr* boe_reg_write(unsigned int reg, unsigned int val)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
    {
        ret = doAXU_Reg_Write(reg, val);
    }

    return ret;
}
/* -------------------  tsu command -------------------------*/
BoeErr* boe_get_s_random(unsigned char *hash, unsigned char *nexthash)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
        return doTSU_GetHash(hash, nexthash);
	
    return ret;
}
BoeErr* boe_valid_sign(unsigned char *sig, unsigned char *pub)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
    {
        ret = doTSU_RecoverPub(sig, pub);
        return ret;
    }

    return ret;
}
BoeErr* boe_valid_sign_recover_pub_async(unsigned char *sig)
{
    BoeErr *ret = bConnected();
    if(ret == BOE_OK)
    {
        return doTSU_RecoverPub_Async(sig);
    }
    else
    {
        printf("boe_valid_sign_recover_pub bConnected error %d\n",ret->ecode);
    }
	
	return ret;
}
BoeErr* boe_valid_sign_callback(BoeValidSignCallback func)
{
    gIns.validsignCallback = func;
    return BOE_OK;
}

