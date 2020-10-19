
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_EVENT_POSTED_H_INCLUDED_
#define _RAP_EVENT_POSTED_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


#define rap_post_event(ev, q)                                                 \
                                                                              \
    if (!(ev)->posted) {                                                      \
        (ev)->posted = 1;                                                     \
        rap_queue_insert_tail(q, &(ev)->queue);                               \
                                                                              \
        rap_log_debug1(RAP_LOG_DEBUG_CORE, (ev)->log, 0, "post event %p", ev);\
                                                                              \
    } else  {                                                                 \
        rap_log_debug1(RAP_LOG_DEBUG_CORE, (ev)->log, 0,                      \
                       "update posted event %p", ev);                         \
    }


#define rap_delete_posted_event(ev)                                           \
                                                                              \
    (ev)->posted = 0;                                                         \
    rap_queue_remove(&(ev)->queue);                                           \
                                                                              \
    rap_log_debug1(RAP_LOG_DEBUG_CORE, (ev)->log, 0,                          \
                   "delete posted event %p", ev);



void rap_event_process_posted(rap_cycle_t *cycle, rap_queue_t *posted);
void rap_event_move_posted_next(rap_cycle_t *cycle);


extern rap_queue_t  rap_posted_accept_events;
extern rap_queue_t  rap_posted_next_events;
extern rap_queue_t  rap_posted_events;


#endif /* _RAP_EVENT_POSTED_H_INCLUDED_ */
