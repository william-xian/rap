
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>


rap_rbtree_t              rap_event_timer_rbtree;
static rap_rbtree_node_t  rap_event_timer_sentinel;

/*
 * the event timer rbtree may contain the duplicate keys, however,
 * it should not be a problem, because we use the rbtree to find
 * a minimum timer value only
 */

rap_int_t
rap_event_timer_init(rap_log_t *log)
{
    rap_rbtree_init(&rap_event_timer_rbtree, &rap_event_timer_sentinel,
                    rap_rbtree_insert_timer_value);

    return RAP_OK;
}


rap_msec_t
rap_event_find_timer(void)
{
    rap_msec_int_t      timer;
    rap_rbtree_node_t  *node, *root, *sentinel;

    if (rap_event_timer_rbtree.root == &rap_event_timer_sentinel) {
        return RAP_TIMER_INFINITE;
    }

    root = rap_event_timer_rbtree.root;
    sentinel = rap_event_timer_rbtree.sentinel;

    node = rap_rbtree_min(root, sentinel);

    timer = (rap_msec_int_t) (node->key - rap_current_msec);

    return (rap_msec_t) (timer > 0 ? timer : 0);
}


void
rap_event_expire_timers(void)
{
    rap_event_t        *ev;
    rap_rbtree_node_t  *node, *root, *sentinel;

    sentinel = rap_event_timer_rbtree.sentinel;

    for ( ;; ) {
        root = rap_event_timer_rbtree.root;

        if (root == sentinel) {
            return;
        }

        node = rap_rbtree_min(root, sentinel);

        /* node->key > rap_current_msec */

        if ((rap_msec_int_t) (node->key - rap_current_msec) > 0) {
            return;
        }

        ev = (rap_event_t *) ((char *) node - offsetof(rap_event_t, timer));

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

        ev->timedout = 1;

        ev->handler(ev);
    }
}


rap_int_t
rap_event_no_timers_left(void)
{
    rap_event_t        *ev;
    rap_rbtree_node_t  *node, *root, *sentinel;

    sentinel = rap_event_timer_rbtree.sentinel;
    root = rap_event_timer_rbtree.root;

    if (root == sentinel) {
        return RAP_OK;
    }

    for (node = rap_rbtree_min(root, sentinel);
         node;
         node = rap_rbtree_next(&rap_event_timer_rbtree, node))
    {
        ev = (rap_event_t *) ((char *) node - offsetof(rap_event_t, timer));

        if (!ev->cancelable) {
            return RAP_AGAIN;
        }
    }

    /* only cancelable timers left */

    return RAP_OK;
}
