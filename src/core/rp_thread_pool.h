
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#ifndef _RP_THREAD_POOL_H_INCLUDED_
#define _RP_THREAD_POOL_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


struct rp_thread_task_s {
    rp_thread_task_t   *next;
    rp_uint_t           id;
    void                *ctx;
    void               (*handler)(void *data, rp_log_t *log);
    rp_event_t          event;
};


typedef struct rp_thread_pool_s  rp_thread_pool_t;


rp_thread_pool_t *rp_thread_pool_add(rp_conf_t *cf, rp_str_t *name);
rp_thread_pool_t *rp_thread_pool_get(rp_cycle_t *cycle, rp_str_t *name);

rp_thread_task_t *rp_thread_task_alloc(rp_pool_t *pool, size_t size);
rp_int_t rp_thread_task_post(rp_thread_pool_t *tp, rp_thread_task_t *task);


#endif /* _RP_THREAD_POOL_H_INCLUDED_ */
