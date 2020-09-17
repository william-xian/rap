
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_EVENT_POSTED_H_INCLUDED_
#define _RP_EVENT_POSTED_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#define rp_post_event(ev, q)                                                 \
                                                                              \
    if (!(ev)->posted) {                                                      \
        (ev)->posted = 1;                                                     \
        rp_queue_insert_tail(q, &(ev)->queue);                               \
                                                                              \
        rp_log_debug1(RP_LOG_DEBUG_CORE, (ev)->log, 0, "post event %p", ev);\
                                                                              \
    } else  {                                                                 \
        rp_log_debug1(RP_LOG_DEBUG_CORE, (ev)->log, 0,                      \
                       "update posted event %p", ev);                         \
    }


#define rp_delete_posted_event(ev)                                           \
                                                                              \
    (ev)->posted = 0;                                                         \
    rp_queue_remove(&(ev)->queue);                                           \
                                                                              \
    rp_log_debug1(RP_LOG_DEBUG_CORE, (ev)->log, 0,                          \
                   "delete posted event %p", ev);



void rp_event_process_posted(rp_cycle_t *cycle, rp_queue_t *posted);
void rp_event_move_posted_next(rp_cycle_t *cycle);


extern rp_queue_t  rp_posted_accept_events;
extern rp_queue_t  rp_posted_next_events;
extern rp_queue_t  rp_posted_events;


#endif /* _RP_EVENT_POSTED_H_INCLUDED_ */
