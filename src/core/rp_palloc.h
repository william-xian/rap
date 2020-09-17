
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_PALLOC_H_INCLUDED_
#define _RP_PALLOC_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


/*
 * RP_MAX_ALLOC_FROM_POOL should be (rp_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define RP_MAX_ALLOC_FROM_POOL  (rp_pagesize - 1)

#define RP_DEFAULT_POOL_SIZE    (16 * 1024)

#define RP_POOL_ALIGNMENT       16
#define RP_MIN_POOL_SIZE                                                     \
    rp_align((sizeof(rp_pool_t) + 2 * sizeof(rp_pool_large_t)),            \
              RP_POOL_ALIGNMENT)


typedef void (*rp_pool_cleanup_pt)(void *data);

typedef struct rp_pool_cleanup_s  rp_pool_cleanup_t;

struct rp_pool_cleanup_s {
    rp_pool_cleanup_pt   handler;
    void                 *data;
    rp_pool_cleanup_t   *next;
};


typedef struct rp_pool_large_s  rp_pool_large_t;

struct rp_pool_large_s {
    rp_pool_large_t     *next;
    void                 *alloc;
};


typedef struct {
    u_char               *last;
    u_char               *end;
    rp_pool_t           *next;
    rp_uint_t            failed;
} rp_pool_data_t;


struct rp_pool_s {
    rp_pool_data_t       d;
    size_t                max;
    rp_pool_t           *current;
    rp_chain_t          *chain;
    rp_pool_large_t     *large;
    rp_pool_cleanup_t   *cleanup;
    rp_log_t            *log;
};


typedef struct {
    rp_fd_t              fd;
    u_char               *name;
    rp_log_t            *log;
} rp_pool_cleanup_file_t;


rp_pool_t *rp_create_pool(size_t size, rp_log_t *log);
void rp_destroy_pool(rp_pool_t *pool);
void rp_reset_pool(rp_pool_t *pool);

void *rp_palloc(rp_pool_t *pool, size_t size);
void *rp_pnalloc(rp_pool_t *pool, size_t size);
void *rp_pcalloc(rp_pool_t *pool, size_t size);
void *rp_pmemalign(rp_pool_t *pool, size_t size, size_t alignment);
rp_int_t rp_pfree(rp_pool_t *pool, void *p);


rp_pool_cleanup_t *rp_pool_cleanup_add(rp_pool_t *p, size_t size);
void rp_pool_run_cleanup_file(rp_pool_t *p, rp_fd_t fd);
void rp_pool_cleanup_file(void *data);
void rp_pool_delete_file(void *data);


#endif /* _RP_PALLOC_H_INCLUDED_ */
