
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _RAP_THREAD_POOL_H_INCLUDED_
#define _RAP_THREAD_POOL_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


struct rap_thread_task_s {
    rap_thread_task_t   *next;
    rap_uint_t           id;
    void                *ctx;
    void               (*handler)(void *data, rap_log_t *log);
    rap_event_t          event;
};


typedef struct rap_thread_pool_s  rap_thread_pool_t;


rap_thread_pool_t *rap_thread_pool_add(rap_conf_t *cf, rap_str_t *name);
rap_thread_pool_t *rap_thread_pool_get(rap_cycle_t *cycle, rap_str_t *name);

rap_thread_task_t *rap_thread_task_alloc(rap_pool_t *pool, size_t size);
rap_int_t rap_thread_task_post(rap_thread_pool_t *tp, rap_thread_task_t *task);


#endif /* _RAP_THREAD_POOL_H_INCLUDED_ */
