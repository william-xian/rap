
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_LIST_H_INCLUDED_
#define _RAP_LIST_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct rap_list_part_s  rap_list_part_t;

struct rap_list_part_s {
    void             *elts;
    rap_uint_t        nelts;
    rap_list_part_t  *next;
};


typedef struct {
    rap_list_part_t  *last;
    rap_list_part_t   part;
    size_t            size;
    rap_uint_t        nalloc;
    rap_pool_t       *pool;
} rap_list_t;


rap_list_t *rap_list_create(rap_pool_t *pool, rap_uint_t n, size_t size);

static rap_inline rap_int_t
rap_list_init(rap_list_t *list, rap_pool_t *pool, rap_uint_t n, size_t size)
{
    list->part.elts = rap_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return RAP_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return RAP_OK;
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


void *rap_list_push(rap_list_t *list);


#endif /* _RAP_LIST_H_INCLUDED_ */
