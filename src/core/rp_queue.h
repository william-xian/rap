
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#ifndef _RP_QUEUE_H_INCLUDED_
#define _RP_QUEUE_H_INCLUDED_


typedef struct rp_queue_s  rp_queue_t;

struct rp_queue_s {
    rp_queue_t  *prev;
    rp_queue_t  *next;
};


#define rp_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q


#define rp_queue_empty(h)                                                    \
    (h == (h)->prev)


#define rp_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


#define rp_queue_insert_after   rp_queue_insert_head


#define rp_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x


#define rp_queue_head(h)                                                     \
    (h)->next


#define rp_queue_last(h)                                                     \
    (h)->prev


#define rp_queue_sentinel(h)                                                 \
    (h)


#define rp_queue_next(q)                                                     \
    (q)->next


#define rp_queue_prev(q)                                                     \
    (q)->prev


#if (RP_DEBUG)

#define rp_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

#define rp_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


#define rp_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;


#define rp_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;


#define rp_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))


rp_queue_t *rp_queue_middle(rp_queue_t *queue);
void rp_queue_sort(rp_queue_t *queue,
    rp_int_t (*cmp)(const rp_queue_t *, const rp_queue_t *));


#endif /* _RP_QUEUE_H_INCLUDED_ */
