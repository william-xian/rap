
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_ARRAY_H_INCLUDED_
#define _RP_ARRAY_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct {
    void        *elts;
    rp_uint_t   nelts;
    size_t       size;
    rp_uint_t   nalloc;
    rp_pool_t  *pool;
} rp_array_t;


rp_array_t *rp_array_create(rp_pool_t *p, rp_uint_t n, size_t size);
void rp_array_destroy(rp_array_t *a);
void *rp_array_push(rp_array_t *a);
void *rp_array_push_n(rp_array_t *a, rp_uint_t n);


static rp_inline rp_int_t
rp_array_init(rp_array_t *array, rp_pool_t *pool, rp_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    array->elts = rp_palloc(pool, n * size);
    if (array->elts == NULL) {
        return RP_ERROR;
    }

    return RP_OK;
}


#endif /* _RP_ARRAY_H_INCLUDED_ */
