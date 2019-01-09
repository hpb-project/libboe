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

#ifndef MSGC_H
#define MSGC_H

#include <stdint.h>
#include "aq.h"
#include "rs.h"

typedef int (*CheckResponse)(uint8_t *res, int len, uint32_t uid);
typedef int (*MsgHandle)(uint8_t *data, int len, void *userdata);
typedef int (*MsgHandleCallback)(uint8_t *data, int len, void *userdata, uint8_t *old_data, int old_len);

typedef struct WMessage WMessage;
typedef void*  MsgContext;
uint8_t *TIMEOUT;
WMessage* WMessageNew(uint32_t uid, CheckResponse cfunc, uint64_t timeout, uint8_t *data, int len, int flag);
int WMessageFree(WMessage *m);

int msgc_init(MsgContext *c, RSContext *rs, MsgHandle msghandle, void*userdata, MsgHandleCallback callback);
int msgc_release(MsgContext *ctx);
int msgc_send(MsgContext *ctx, WMessage *wmsg);
AQData* msgc_read(MsgContext *ctx, WMessage *wmsg);
long int g_send;
long int g_rsvd;
long int g_timeout;
long int g_bmatch0;
long int g_tsu_rcv;

#endif  /*MSGC_H*/
