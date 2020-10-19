
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


rap_queue_t  rap_posted_accept_events;
rap_queue_t  rap_posted_next_events;
rap_queue_t  rap_posted_events;


void
rap_event_process_posted(rap_cycle_t *cycle, rap_queue_t *posted)
{
    rap_queue_t  *q;
    rap_event_t  *ev;

    while (!rap_queue_empty(posted)) {

        q = rap_queue_head(posted);
        ev = rap_queue_data(q, rap_event_t, queue);

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted event %p", ev);

        rap_delete_posted_event(ev);

        ev->handler(ev);
    }
}


void
rap_event_move_posted_next(rap_cycle_t *cycle)
{
    rap_queue_t  *q;
    rap_event_t  *ev;

    for (q = rap_queue_head(&rap_posted_next_events);
         q != rap_queue_sentinel(&rap_posted_next_events);
         q = rap_queue_next(q))
    {
        ev = rap_queue_data(q, rap_event_t, queue);

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, cycle->log, 0,
                      "posted next event %p", ev);

        ev->ready = 1;
        ev->available = -1;
    }

    rap_queue_add(&rap_posted_events, &rap_posted_next_events);
    rap_queue_init(&rap_posted_next_events);
}
