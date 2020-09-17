
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_LIST_H_INCLUDED_
#define _RP_LIST_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct rp_list_part_s  rp_list_part_t;

struct rp_list_part_s {
    void             *elts;
    rp_uint_t        nelts;
    rp_list_part_t  *next;
};


typedef struct {
    rp_list_part_t  *last;
    rp_list_part_t   part;
    size_t            size;
    rp_uint_t        nalloc;
    rp_pool_t       *pool;
} rp_list_t;


rp_list_t *rp_list_create(rp_pool_t *pool, rp_uint_t n, size_t size);

static rp_inline rp_int_t
rp_list_init(rp_list_t *list, rp_pool_t *pool, rp_uint_t n, size_t size)
{
    list->part.elts = rp_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return RP_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return RP_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *rp_list_push(rp_list_t *list);


#endif /* _RP_LIST_H_INCLUDED_ */
