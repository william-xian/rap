
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


rp_array_t *
rp_array_create(rp_pool_t *p, rp_uint_t n, size_t size)
{
    rp_array_t *a;

    a = rp_palloc(p, sizeof(rp_array_t));
    if (a == NULL) {
        return NULL;
    }

    if (rp_array_init(a, p, n, size) != RP_OK) {
        return NULL;
    }

    return a;
}


void
rp_array_destroy(rp_array_t *a)
{
    rp_pool_t  *p;

    p = a->pool;

    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }

    if ((u_char *) a + sizeof(rp_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}


void *
rp_array_push(rp_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    rp_pool_t  *p;

    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;

        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += a->size;
            a->nalloc++;

        } else {
            /* allocate a new array */

            new = rp_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }

            rp_memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;

    return elt;
}


void *
rp_array_push_n(rp_array_t *a, rp_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    rp_uint_t   nalloc;
    rp_pool_t  *p;

    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;
            a->nalloc += n;

        } else {
            /* allocate a new array */

            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = rp_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            rp_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;

    return elt;
}
