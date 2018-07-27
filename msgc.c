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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>  
#include <sys/types.h>  
#include <sys/stat.h> 
#include <pthread.h>
#include <semaphore.h>
#include "common.h"
#include "rs.h"
#include "atomic.h"
#include "aq.h"
#include "list.h"
#include "msgc.h"



// wait response. 
typedef struct WMessage{
    uint32_t uid;     // unique id.
    uint32_t timeout; // timeout unit us.
    uint64_t sTime;   // timestamp of enter wait list..
    sem_t sem;
    CheckResponse cFunc; // check response is waited.
    AQData s;
    AQData *d;

}WMessage;

// wait list.
typedef struct WaitNode{
    WMessage *wmsg;
    struct list_head list; 
}WaitNode;

typedef struct IMsgContext{
    AtomicQ  r_q;
    WaitNode wList;
    pthread_t r_thread; // receive msg thread.
    pthread_t s_thread; // sorting msg thread.
    MsgHandle msgHandleFunc; // deal msg function.
    uint8_t  th_flag;  // thread control.
    RSContext *rs;
    void*    userdata;
    pthread_mutex_t mlock; // 
}IMsgContext;

static void *sorting_thread(void*userdata);
static void *receive_thread(void*userdata);

WMessage* WMessageNew(uint32_t uid, CheckResponse cfunc, uint32_t timeout, uint8_t *data, int len)
{
    WMessage *msg = (WMessage*)malloc(sizeof(WMessage));
    int align = len;
    if(msg == NULL)
    {
        return NULL;
    }
    msg->uid = uid;
    msg->cFunc = cfunc;
    msg->timeout = timeout*1000;
    msg->d = NULL;
    if(align%4 != 0)
    {
        align += (4-align%4);
    }
    msg->s.buf = malloc(align);
    msg->s.len = align;
    if(msg->s.buf == NULL)
    {
        free(msg);
        return NULL;
    }
    memset(msg->s.buf, 0x0, align);
    memcpy(msg->s.buf, data, len);

    if(sem_init(&msg->sem, 0, 0) < 0)
    {
        free(msg->s.buf);
        free(msg);
        return NULL;
    }

    return msg;
}

int WMessageFree(WMessage *m)
{
    sem_destroy(&m->sem);
    if(m->s.buf != NULL)
    {
        free(m->s.buf);
        m->s.buf = NULL;
    }
    free(m);
    return 0;
}

int msgc_init(MsgContext *ctx, RSContext *rs, MsgHandle msghandle, void*userdata)
{
    int ret = 0;
    IMsgContext *c = (IMsgContext*)malloc(sizeof(IMsgContext));
    memset(c, 0, sizeof(IMsgContext));


    INIT_LIST_HEAD(&c->wList.list);
    ret = aq_init(&(c->r_q), 1000000); // 100w
    if(ret != 0)
    {
        free(c);
        return ret;
    }
    c->msgHandleFunc = msghandle;
    c->rs = rs;
    c->th_flag = 0; // post thread.
    c->userdata = userdata;

    ret = pthread_create(&c->r_thread, NULL, receive_thread, (void*)c);
    ret = pthread_create(&c->s_thread, NULL, sorting_thread, (void*)c);
    c->th_flag = 1; // start thread.
    *ctx = c;

    return 0;
}

int msgc_release(MsgContext *ctx)
{
    IMsgContext *c = *ctx;
    c->th_flag = 2;
    pthread_join(c->r_thread, NULL);
    pthread_join(c->s_thread, NULL);
    pthread_mutex_destroy(&c->mlock);
    aq_free(&(c->r_q));
    
    return 0;
}

int msgc_send(MsgContext *ctx, WMessage *wmsg)
{
    IMsgContext *c = *ctx;
    //int ret = 0;
    WaitNode *n = (WaitNode*)malloc(sizeof(WaitNode));
    if(n == NULL)
        return -1;
    wmsg->sTime = get_timestamp_us();
    n->wmsg = wmsg;

    if(RSWrite(c->rs, wmsg->s.buf, wmsg->s.len) < 0)
    {
        free(n);
        return -1;
    }

    pthread_mutex_lock(&c->mlock);
    list_add_tail(&(n->list), &(c->wList.list));
    pthread_mutex_unlock(&c->mlock);

    return 0;
}

AQData* msgc_read(MsgContext *ctx, WMessage *wmsg)
{
    sem_wait(&wmsg->sem);
    return wmsg->d;
}

static void *receive_thread(void*userdata)
{
    IMsgContext *c = (IMsgContext*)userdata;
    int ret = 0;
    int cycle_ms = 20;

    static uint8_t buf[64*1024];
    int max_package_len;
    while(c->th_flag == 0) ; // wait thread start.
    while(c->th_flag == 1)
    {
        max_package_len = sizeof(buf);
        ret = RSSelect(c->rs, cycle_ms);
        if(ret < 0)
        {
            fprintf(stderr, "select error.\n");
            continue;
        }
        else if(ret == 0)
        {
            // timeout.
        }
        else {
            ret = RSRead(c->rs, buf, &max_package_len);
            if(ret == 0)
            {
                AQData *d = aqd_new(max_package_len);
                memcpy(d->buf, buf, max_package_len);
                aq_push(&c->r_q, d);
            }
        }
    }
    return NULL;

}

static void *sorting_thread(void*userdata)
{
    IMsgContext *c = (IMsgContext*)userdata;
    WaitNode *head = &c->wList;
    WaitNode *pnode = NULL;
    struct list_head *pos, *next; 
    WMessage *m = NULL;
    AQData *d = NULL;
    uint8_t bmatch = 0;
    uint64_t ts, te;
    int cycle_ms = 1;


    while(c->th_flag == 0) ; // wait thread start.
    // main loop.
    while(c->th_flag == 1)
    {
        bmatch = 0;
        ts = get_timestamp_us();
        d = aq_pop(&(c->r_q));
        if(d != NULL)
        {
            list_for_each_safe(pos, next, &head->list) 
            { 
                pnode = list_entry(pos, WaitNode, list); 
                m = pnode->wmsg;

                if(d->len > 0 && d->buf != NULL &&
                        (1 == m->cFunc(d->buf, d->len, m->uid)))
                {
                    bmatch = 1;
                    m->d = d;
                    sem_post(&m->sem);

                    pthread_mutex_lock(&c->mlock);
                    list_del_init(pos);
                    pthread_mutex_unlock(&c->mlock);
                    free(pnode);
                    break;
                }
            } 
            if(bmatch == 0 && c->msgHandleFunc != NULL)
            {
                c->msgHandleFunc(d->buf, d->len, c->userdata);
                aqd_free(d);
            }

        }

        list_for_each_safe(pos, next, &head->list) 
        { 
            pnode = list_entry(pos, WaitNode, list); 
            m = pnode->wmsg;
            if((m->sTime + m->timeout) <= (get_timestamp_us()))
            {
                m->d = NULL;
                // timeout.
                sem_post(&m->sem);
                pthread_mutex_lock(&c->mlock);
                list_del_init(pos);
                pthread_mutex_unlock(&c->mlock);
                free(pnode);
            }
        } 
        te = get_timestamp_us();
        if(((te - ts)/1000) < cycle_ms)
        {
            //usleep(cycle_ms*1000 - (te-ts));
        }
    }
    {
        
        list_for_each_safe(pos, next, &head->list) 
        { 
            pnode = list_entry(pos, WaitNode, list); 
            m = pnode->wmsg;
            m->d = NULL;
            sem_post(&m->sem);
            pthread_mutex_lock(&c->mlock);
            list_del_init(pos);
            pthread_mutex_unlock(&c->mlock);
            free(pnode);
        } 
    }

    return NULL;
}

