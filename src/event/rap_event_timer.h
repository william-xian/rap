
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_EVENT_TIMER_H_INCLUDED_
#define _RAP_EVENT_TIMER_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


#define RAP_TIMER_INFINITE  (rap_msec_t) -1

#define RAP_TIMER_LAZY_DELAY  300


rap_int_t rap_event_timer_init(rap_log_t *log);
rap_msec_t rap_event_find_timer(void);
void rap_event_expire_timers(void);
rap_int_t rap_event_no_timers_left(void);


extern rap_rbtree_t  rap_event_timer_rbtree;


static rap_inline void
rap_event_del_timer(rap_event_t *ev)
{
    rap_log_debug2(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "event timer del: %d: %M",
                    rap_event_ident(ev->data), ev->timer.key);

    rap_rbtree_delete(&rap_event_timer_rbtree, &ev->timer);

#if (RAP_DEBUG)
    ev->timer.left = NULL;
    ev->timer.right = NULL;
    ev->timer.parent = NULL;
#endif

    ev->timer_set = 0;
}


static rap_inline void
rap_event_add_timer(rap_event_t *ev, rap_msec_t timer)
{
    rap_msec_t      key;
    rap_msec_int_t  diff;

    key = rap_current_msec + timer;

    if (ev->timer_set) {

        /*
         * Use a previous timer value if difference between it and a new
         * value is less than RAP_TIMER_LAZY_DELAY milliseconds: this allows
         * to minimize the rbtree operations for fast connections.
         */

        diff = (rap_msec_int_t) (key - ev->timer.key);

        if (rap_abs(diff) < RAP_TIMER_LAZY_DELAY) {
            rap_log_debug3(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                           "event timer: %d, old: %M, new: %M",
                            rap_event_ident(ev->data), ev->timer.key, key);
            return;
        }

        rap_del_timer(ev);
    }

    ev->timer.key = key;

    rap_log_debug3(RAP_LOG_DEBUG_EVENT, ev->log, 0,
                   "event timer add: %d: %M:%M",
                    rap_event_ident(ev->data), timer, ev->timer.key);

    rap_rbtree_insert(&rap_event_timer_rbtree, &ev->timer);

    ev->timer_set = 1;
}


#endif /* _RAP_EVENT_TIMER_H_INCLUDED_ */
