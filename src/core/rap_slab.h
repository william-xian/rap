
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_SLAB_H_INCLUDED_
#define _RAP_SLAB_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct rap_slab_page_s  rap_slab_page_t;

struct rap_slab_page_s {
    uintptr_t         slab;
    rap_slab_page_t  *next;
    uintptr_t         prev;
};


typedef struct {
    rap_uint_t        total;
    rap_uint_t        used;

    rap_uint_t        reqs;
    rap_uint_t        fails;
} rap_slab_stat_t;


typedef struct {
    rap_shmtx_sh_t    lock;

    size_t            min_size;
    size_t            min_shift;

    rap_slab_page_t  *pages;
    rap_slab_page_t  *last;
    rap_slab_page_t   free;

    rap_slab_stat_t  *stats;
    rap_uint_t        pfree;

    u_char           *start;
    u_char           *end;

    rap_shmtx_t       mutex;

    u_char           *log_ctx;
    u_char            zero;

    unsigned          log_nomem:1;

    void             *data;
    void             *addr;
} rap_slab_pool_t;


void rap_slab_sizes_init(void);
void rap_slab_init(rap_slab_pool_t *pool);
void *rap_slab_alloc(rap_slab_pool_t *pool, size_t size);
void *rap_slab_alloc_locked(rap_slab_pool_t *pool, size_t size);
void *rap_slab_calloc(rap_slab_pool_t *pool, size_t size);
void *rap_slab_calloc_locked(rap_slab_pool_t *pool, size_t size);
void rap_slab_free(rap_slab_pool_t *pool, void *p);
void rap_slab_free_locked(rap_slab_pool_t *pool, void *p);


#endif /* _RAP_SLAB_H_INCLUDED_ */
