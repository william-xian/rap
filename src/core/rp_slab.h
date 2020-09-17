
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_SLAB_H_INCLUDED_
#define _RP_SLAB_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct rp_slab_page_s  rp_slab_page_t;

struct rp_slab_page_s {
    uintptr_t         slab;
    rp_slab_page_t  *next;
    uintptr_t         prev;
};


typedef struct {
    rp_uint_t        total;
    rp_uint_t        used;

    rp_uint_t        reqs;
    rp_uint_t        fails;
} rp_slab_stat_t;


typedef struct {
    rp_shmtx_sh_t    lock;

    size_t            min_size;
    size_t            min_shift;

    rp_slab_page_t  *pages;
    rp_slab_page_t  *last;
    rp_slab_page_t   free;

    rp_slab_stat_t  *stats;
    rp_uint_t        pfree;

    u_char           *start;
    u_char           *end;

    rp_shmtx_t       mutex;

    u_char           *log_ctx;
    u_char            zero;

    unsigned          log_nomem:1;

    void             *data;
    void             *addr;
} rp_slab_pool_t;


void rp_slab_sizes_init(void);
void rp_slab_init(rp_slab_pool_t *pool);
void *rp_slab_alloc(rp_slab_pool_t *pool, size_t size);
void *rp_slab_alloc_locked(rp_slab_pool_t *pool, size_t size);
void *rp_slab_calloc(rp_slab_pool_t *pool, size_t size);
void *rp_slab_calloc_locked(rp_slab_pool_t *pool, size_t size);
void rp_slab_free(rp_slab_pool_t *pool, void *p);
void rp_slab_free_locked(rp_slab_pool_t *pool, void *p);


#endif /* _RP_SLAB_H_INCLUDED_ */
