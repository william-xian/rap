
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


rp_queue_t  rp_posted_accept_events;
rp_queue_t  rp_posted_next_events;
rp_queue_t  rp_posted_events;


void
rp_event_process_posted(rp_cycle_t *cycle, rp_queue_t *posted)
{
    rp_queue_t  *q;
    rp_event_t  *ev;

    while (!rp_queue_empty(posted)) {

        q = rp_queue_head(posted);
        ev = rp_queue_data(q, rp_event_t, queue);

        rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        rp_delete_posted_event(ev);

        ev->handler(ev);
    }
}


void
rp_event_move_posted_next(rp_cycle_t *cycle)
{
    rp_queue_t  *q;
    rp_event_t  *ev;

    for (q = rp_queue_head(&rp_posted_next_events);
         q != rp_queue_sentinel(&rp_posted_next_events);
         q = rp_queue_next(q))
    {
        ev = rp_queue_data(q, rp_event_t, queue);

        rp_log_debug1(RP_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);

        ev->ready = 1;
        ev->available = -1;
    }

    rp_queue_add(&rp_posted_events, &rp_posted_next_events);
    rp_queue_init(&rp_posted_next_events);
}
