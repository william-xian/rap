
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


rp_list_t *
rp_list_create(rp_pool_t *pool, rp_uint_t n, size_t size)
{
    rp_list_t  *list;

    list = rp_palloc(pool, sizeof(rp_list_t));
    if (list == NULL) {
        return NULL;
    }

    if (rp_list_init(list, pool, n, size) != RP_OK) {
        return NULL;
    }

    return list;
}


void *
rp_list_push(rp_list_t *l)
{
    void             *elt;
    rp_list_part_t  *last;

    last = l->last;

    if (last->nelts == l->nalloc) {

        /* the last part is full, allocate a new list part */

        last = rp_palloc(l->pool, sizeof(rp_list_part_t));
        if (last == NULL) {
            return NULL;
        }

        last->elts = rp_palloc(l->pool, l->nalloc * l->size);
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
