
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_EVENT_TIMER_H_INCLUDED_
#define _RP_EVENT_TIMER_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


#define RP_TIMER_INFINITE  (rp_msec_t) -1

#define RP_TIMER_LAZY_DELAY  300


rp_int_t rp_event_timer_init(rp_log_t *log);
rp_msec_t rp_event_find_timer(void);
void rp_event_expire_timers(void);
rp_int_t rp_event_no_timers_left(void);


extern rp_rbtree_t  rp_event_timer_rbtree;


static rp_inline void
rp_event_del_timer(rp_event_t *ev)
{
    rp_log_debug2(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "event timer del: %d: %M",
                    rp_event_ident(ev->data), ev->timer.key);

    rp_rbtree_delete(&rp_event_timer_rbtree, &ev->timer);

#if (RP_DEBUG)
    ev->timer.left = NULL;
    ev->timer.right = NULL;
    ev->timer.parent = NULL;
#endif

    ev->timer_set = 0;
}


static rp_inline void
rp_event_add_timer(rp_event_t *ev, rp_msec_t timer)
{
    rp_msec_t      key;
    rp_msec_int_t  diff;

    key = rp_current_msec + timer;

    if (ev->timer_set) {

        /*
         * Use a previous timer value if difference between it and a new
         * value is less than RP_TIMER_LAZY_DELAY milliseconds: this allows
         * to minimize the rbtree operations for fast connections.
         */

        diff = (rp_msec_int_t) (key - ev->timer.key);

        if (rp_abs(diff) < RP_TIMER_LAZY_DELAY) {
            rp_log_debug3(RP_LOG_DEBUG_EVENT, ev->log, 0,
                           "event timer: %d, old: %M, new: %M",
                            rp_event_ident(ev->data), ev->timer.key, key);
            return;
        }

        rp_del_timer(ev);
    }

    ev->timer.key = key;

    rp_log_debug3(RP_LOG_DEBUG_EVENT, ev->log, 0,
                   "event timer add: %d: %M:%M",
                    rp_event_ident(ev->data), timer, ev->timer.key);

    rp_rbtree_insert(&rp_event_timer_rbtree, &ev->timer);

    ev->timer_set = 1;
}


#endif /* _RP_EVENT_TIMER_H_INCLUDED_ */
