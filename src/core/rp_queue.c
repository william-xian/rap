
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


/*
 * find the middle queue element if the queue has odd number of elements
 * or the first element of the queue's second part otherwise
 */

rp_queue_t *
rp_queue_middle(rp_queue_t *queue)
{
    rp_queue_t  *middle, *next;

    middle = rp_queue_head(queue);

    if (middle == rp_queue_last(queue)) {
        return middle;
    }

    next = rp_queue_head(queue);

    for ( ;; ) {
        middle = rp_queue_next(middle);

        next = rp_queue_next(next);

        if (next == rp_queue_last(queue)) {
            return middle;
        }

        next = rp_queue_next(next);

        if (next == rp_queue_last(queue)) {
            return middle;
        }
    }
}


/* the stable insertion sort */

void
rp_queue_sort(rp_queue_t *queue,
    rp_int_t (*cmp)(const rp_queue_t *, const rp_queue_t *))
{
    rp_queue_t  *q, *prev, *next;

    q = rp_queue_head(queue);

    if (q == rp_queue_last(queue)) {
        return;
    }

    for (q = rp_queue_next(q); q != rp_queue_sentinel(queue); q = next) {

        prev = rp_queue_prev(q);
        next = rp_queue_next(q);

        rp_queue_remove(q);

        do {
            if (cmp(prev, q) <= 0) {
                break;
            }

            prev = rp_queue_prev(prev);

        } while (prev != rp_queue_sentinel(queue));

        rp_queue_insert_after(prev, q);
    }
}
