
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


rap_list_t *
rap_list_create(rap_pool_t *pool, rap_uint_t n, size_t size)
{
    rap_list_t  *list;

    list = rap_palloc(pool, sizeof(rap_list_t));
    if (list == NULL) {
        return NULL;
    }

    if (rap_list_init(list, pool, n, size) != RAP_OK) {
        return NULL;
    }

    return list;
}


void *
rap_list_push(rap_list_t *l)
{
    void             *elt;
    rap_list_part_t  *last;

    last = l->last;

    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */

        last = rap_palloc(l->pool, sizeof(rap_list_part_t));
        if (last == NULL) {
            return NULL;
        }

        last->elts = rap_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        l->last->next = last;
        l->last = last;
    }

    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;

    return elt;
}
