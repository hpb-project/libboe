// Last Update:2018-06-18 15:36:31
/**
 * @file type.h
 * @brief 
 * @author luxueqian
 * @version 0.1.00
 * @date 2018-06-16
 */

#ifndef TYPE_H
#define TYPE_H

#include <stdint.h>
typedef void*   Handle_t;
typedef int (*MsgHandle)(uint8_t *data, int len, void *userdata);

#endif  /*TYPE_H*/
