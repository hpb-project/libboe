// Last Update:2018-08-10 17:19:06
/**
 * @file serror.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-20
 */

#ifndef SERROR_H
#define SERROR_H
#include "boe.h"
#include "axu_connector.h"

BoeErr e_ok;
BoeErr e_init_fail;
BoeErr e_conn_fail;
BoeErr e_no_device;
BoeErr e_no_mem;
BoeErr e_param_invalid;
BoeErr e_msgc_send_fail;
BoeErr e_msgc_read_timeout;
BoeErr e_result_invalid;
BoeErr e_image_chk_error;
BoeErr e_image_header_error;
BoeErr e_gen_host_id_failed;
BoeErr e_hw_verify_failed;
BoeErr e_update_ver_not_match;
BoeErr e_update_reboot_failed;
BoeErr e_axu_inner[MAX_AXU_ERRNUM];
BoeErr e_hash_get_time_limit;
BoeErr e_hash_check_error;
BoeErr e_checksum_error;


#endif  /*SERROR_H*/
