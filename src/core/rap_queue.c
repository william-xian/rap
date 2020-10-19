
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


/*
 * find the middle queue element if the queue has odd number of elements
 * or the first element of the queue's second part otherwise
 */

rap_queue_t *
rap_queue_middle(rap_queue_t *queue)
{
    rap_queue_t  *middle, *next;

    middle = rap_queue_head(queue);

    if (middle == rap_queue_last(queue)) {
        return middle;
    }

    next = rap_queue_head(queue);

    for ( ;; ) {
        middle = rap_queue_next(middle);

        next = rap_queue_next(next);

        if (next == rap_queue_last(queue)) {
            return middle;
        }

        next = rap_queue_next(next);

        if (next == rap_queue_last(queue)) {
            return middle;
        }
    }
}


/* the stable insertion sort */

void
rap_queue_sort(rap_queue_t *queue,
    rap_int_t (*cmp)(const rap_queue_t *, const rap_queue_t *))
{
    rap_queue_t  *q, *prev, *next;

    q = rap_queue_head(queue);

    if (q == rap_queue_last(queue)) {
        return;
    }

    for (q = rap_queue_next(q); q != rap_queue_sentinel(queue); q = next) {

        prev = rap_queue_prev(q);
        next = rap_queue_next(q);

        rap_queue_remove(q);

        do {
            if (cmp(prev, q) <= 0) {
                break;
            }

            prev = rap_queue_prev(prev);

        } while (prev != rap_queue_sentinel(queue));

        rap_queue_insert_after(prev, q);
    }
}
