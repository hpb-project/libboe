// Last Update:2018-08-16 22:26:57
/**
 * @file doAXU.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-21
 */

#ifndef DO_A_X_U_H
#define DO_A_X_U_H

#include "boe_full.h"
#include "axu_connector.h"

BoeErr* doAXU_Init(char *ethname, MsgHandle msghandle, void*userdata);
BoeErr* doAXU_Release();
BoeErr* doAXU_GetVersionInfo(unsigned char *H, unsigned char *M, unsigned char *F, unsigned char *D);
BoeErr* doAXU_Reset(void);
BoeErr* doAXU_GetRandom(unsigned char *rdm);
BoeErr* doAXU_GetBOESN(unsigned char *sn);
BoeErr* doAXU_GetHWVer(TVersion *hw);
BoeErr* doAXU_GetFWVer(TVersion *fw);
BoeErr* doAXU_GetAXUVer(TVersion *axu);
BoeErr* doAXU_SetBoeSN(unsigned char *sn);
BoeErr* doAXU_BindAccount(uint8_t *baccount);
BoeErr* doAXU_GetBindAccount(uint8_t *account);
BoeErr* doAXU_HWSign(uint8_t *data, uint8_t *result);
BoeErr* doAXU_Transport(ImageHeader *info, uint8_t *data);
BoeErr* doAXU_UpgradeStart(uint32_t fid);
BoeErr* doAXU_UpgradeAbort(uint32_t fid);

BoeErr* doAXU_Genkey(unsigned char *pubkey);
BoeErr* doAXU_Get_Pubkey(unsigned char *pubkey);
BoeErr* doAXU_Lock_PK(void);
BoeErr* doAXU_HW_Verify(unsigned char *hash, unsigned char *signature, unsigned char *pubkey);
BoeErr* doAXU_Set_MAC(unsigned char *mac);
BoeErr* doAXU_Get_MAC(unsigned char *mac);
BoeErr* doAXU_Phy_Read(uint32_t reg, uint16_t *val);
BoeErr* doAXU_Phy_Shd_Read(uint32_t reg, uint16_t shadow, uint16_t *val);
BoeErr* doAXU_Reg_Read(uint32_t reg, uint32_t *val);
BoeErr* doAXU_Reg_Write(uint32_t reg, uint32_t val);

#endif  /*DO_A_X_U_H*/
