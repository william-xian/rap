
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#ifndef _RAP_QUEUE_H_INCLUDED_
#define _RAP_QUEUE_H_INCLUDED_


typedef struct rap_queue_s  rap_queue_t;

struct rap_queue_s {
    rap_queue_t  *prev;
    rap_queue_t  *next;
};


#define rap_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q


#define rap_queue_empty(h)                                                    \
    (h == (h)->prev)


#define rap_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


#define rap_queue_insert_after   rap_queue_insert_head


#define rap_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x


#define rap_queue_head(h)                                                     \
    (h)->next


#define rap_queue_last(h)                                                     \
    (h)->prev


#define rap_queue_sentinel(h)                                                 \
    (h)


#define rap_queue_next(q)                                                     \
    (q)->next


#define rap_queue_prev(q)                                                     \
    (q)->prev


#if (RAP_DEBUG)

#define rap_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

#define rap_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


#define rap_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;


#define rap_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;


#define rap_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))


rap_queue_t *rap_queue_middle(rap_queue_t *queue);
void rap_queue_sort(rap_queue_t *queue,
    rap_int_t (*cmp)(const rap_queue_t *, const rap_queue_t *));


#endif /* _RAP_QUEUE_H_INCLUDED_ */
