// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

#ifndef AXU_CONNECTOR_H
#define AXU_CONNECTOR_H
#include <stdint.h>
#include "common.h"
#include "rs.h"


typedef enum {
    AP_QUERY = 0,
    AP_RESPONSE = 1
}AP_Type;

typedef struct A_PACKAGE_HEADER {
    uint16_t magic_aacc;
    uint16_t package_id;
    uint16_t body_length;
    uint8_t  acmd;
    uint8_t  q_or_r; // AP_QUERY is query and AP_RESPONSE is response.
    uint16_t reversed;
    uint16_t magic_ccaa;
}A_Package_Header;

typedef struct A_PACKAGE{
    A_Package_Header header;
    uint32_t    checksum;
    uint8_t     data[];
}A_Package;

typedef struct Tversion {
    unsigned char H;
    unsigned char M;
    unsigned char F;
    unsigned char D;
}TVersion;

#define PACKAGE_MAX_SIZE 	(RS_MAX_PACKAGE_LEN - 4 - sizeof(A_Package))   // 2KB
#define MAX_AXU_ERRNUM (30)
#define AXU_MAGIC_START (0xaacc)
#define AXU_MAGIC_END   (0xccaa)

typedef enum A_CMD {
    ACMD_START = 0x0,
    ACMD_PB_GET_VERSION_INFO    = 0x01,
    ACMD_PB_TRANSPORT_START     = 0x02,
    ACMD_PB_TRANSPORT_MIDDLE    = 0x03,
    ACMD_PB_TRANSPORT_FINISH    = 0x04,
    ACMD_PB_UPGRADE_START       = 0x05,
    ACMD_PB_UPGRADE_ABORT       = 0x06,
    ACMD_PB_RESET               = 0x07,
    ACMD_PB_GET_RANDOM          = 0x08,
    ACMD_PB_GET_SN           = 0x09,
    ACMD_PB_GET_HW_VER          = 0x0A,
    ACMD_PB_GET_FW_VER          = 0x0B,
    ACMD_PB_GET_AXU_VER         = 0x0C,
    ACMD_PB_SET_SN           = 0x0D,

	//ACMD_PB_CHECK_BIND			= 0x0E,
	//ACMD_PB_BIND_ID				= 0x0F,
	ACMD_PB_BIND_ACCOUNT		= 0x10,
	ACMD_PB_HW_SIGN				= 0x11,
	//ACMD_PB_UNBIND				= 0x12,
	ACMD_PB_GET_ACCOUNT		= 0x13,

	ACMD_PB_GENKEY			= 0x14,
	ACMD_PB_GET_PUBKEY		= 0x15,
	ACMD_PB_LOCK_PRIKEY		= 0x16,
	ACMD_PB_VERIFY		= 0x17,

	ACMD_PB_SET_MAC		= 0x18,
	ACMD_PB_GET_MAC		= 0x19,
	ACMD_PB_PHY_READ    = 0x20,
    ACMD_PB_PHY_SHD_READ    = 0x21, // shadow register read
    ACMD_PB_PHY_SHD_WRITE   = 0x22, // shadow register write
    ACMD_PB_REG_WRITE       = 0x23,
    ACMD_PB_REG_READ        = 0x24,

    ACMD_PB_REG_RANDOM		= 0x25,



    ACMD_BP_RES_ACK             = 0x51,
    ACMD_BP_RES_ERR             = 0x52,
    ACMD_BP_RES_UPGRADE_PROGRESS= 0x53,

    ACMD_END                    = 0xff,
}ACmd;

typedef struct ImageHeader{
    uint8_t usage;
    uint8_t vendor[3];
    uint32_t chk;
    uint32_t len;
    TVersion version;
}ImageHeader;

A_Package* axu_package_new(uint32_t len);
int axu_package_free(A_Package* pack);

void axu_package_init(A_Package *pack, A_Package* req, ACmd cmd);

int axu_set_data(A_Package *pack, int offset, uint8_t *data, int len);
int axu_package_len(A_Package *pack);

void axu_finish_package(A_Package *pack);

#endif  /*AXU_CONNECTOR_H*/
