
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>


rp_rbtree_t              rp_event_timer_rbtree;
static rp_rbtree_node_t  rp_event_timer_sentinel;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

rp_int_t
rp_event_timer_init(rp_log_t *log)
{
    rp_rbtree_init(&rp_event_timer_rbtree, &rp_event_timer_sentinel,
                    rp_rbtree_insert_timer_value);

    return RP_OK;
}


rp_msec_t
rp_event_find_timer(void)
{
    rp_msec_int_t      timer;
    rp_rbtree_node_t  *node, *root, *sentinel;

    if (rp_event_timer_rbtree.root == &rp_event_timer_sentinel) {
        return RP_TIMER_INFINITE;
    }

    root = rp_event_timer_rbtree.root;
    sentinel = rp_event_timer_rbtree.sentinel;

    node = rp_rbtree_min(root, sentinel);

    timer = (rp_msec_int_t) (node->key - rp_current_msec);

    return (rp_msec_t) (timer > 0 ? timer : 0);
}


void
rp_event_expire_timers(void)
{
    rp_event_t        *ev;
    rp_rbtree_node_t  *node, *root, *sentinel;

    sentinel = rp_event_timer_rbtree.sentinel;

    for ( ;; ) {
        root = rp_event_timer_rbtree.root;

        if (root == sentinel) {
            return;
        }

        node = rp_rbtree_min(root, sentinel);

        /* node->key > rp_current_msec */

        if ((rp_msec_int_t) (node->key - rp_current_msec) > 0) {
            return;
        }

        ev = (rp_event_t *) ((char *) node - offsetof(rp_event_t, timer));

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

        ev->timedout = 1;

        ev->handler(ev);
    }
}


rp_int_t
rp_event_no_timers_left(void)
{
    rp_event_t        *ev;
    rp_rbtree_node_t  *node, *root, *sentinel;

    sentinel = rp_event_timer_rbtree.sentinel;
    root = rp_event_timer_rbtree.root;

    if (root == sentinel) {
        return RP_OK;
    }

    for (node = rp_rbtree_min(root, sentinel);
         node;
         node = rp_rbtree_next(&rp_event_timer_rbtree, node))
    {
        ev = (rp_event_t *) ((char *) node - offsetof(rp_event_t, timer));

        if (!ev->cancelable) {
            return RP_AGAIN;
        }
    }

    /* only cancelable timers left */

    return RP_OK;
}
