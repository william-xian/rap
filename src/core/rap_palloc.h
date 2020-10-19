
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_PALLOC_H_INCLUDED_
#define _RAP_PALLOC_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


/*
 * RAP_MAX_ALLOC_FROM_POOL should be (rap_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define RAP_MAX_ALLOC_FROM_POOL  (rap_pagesize - 1)

#define RAP_DEFAULT_POOL_SIZE    (16 * 1024)

#define RAP_POOL_ALIGNMENT       16
#define RAP_MIN_POOL_SIZE                                                     \
    rap_align((sizeof(rap_pool_t) + 2 * sizeof(rap_pool_large_t)),            \
              RAP_POOL_ALIGNMENT)


typedef void (*rap_pool_cleanup_pt)(void *data);

typedef struct rap_pool_cleanup_s  rap_pool_cleanup_t;

struct rap_pool_cleanup_s {
    rap_pool_cleanup_pt   handler;
    void                 *data;
    rap_pool_cleanup_t   *next;
};


typedef struct rap_pool_large_s  rap_pool_large_t;

struct rap_pool_large_s {
    rap_pool_large_t     *next;
    void                 *alloc;
};


typedef struct {
    u_char               *last;
    u_char               *end;
    rap_pool_t           *next;
    rap_uint_t            failed;
} rap_pool_data_t;


struct rap_pool_s {
    rap_pool_data_t       d;
    size_t                max;
    rap_pool_t           *current;
    rap_chain_t          *chain;
    rap_pool_large_t     *large;
    rap_pool_cleanup_t   *cleanup;
    rap_log_t            *log;
};


typedef struct {
    rap_fd_t              fd;
    u_char               *name;
    rap_log_t            *log;
} rap_pool_cleanup_file_t;


rap_pool_t *rap_create_pool(size_t size, rap_log_t *log);
void rap_destroy_pool(rap_pool_t *pool);
void rap_reset_pool(rap_pool_t *pool);

void *rap_palloc(rap_pool_t *pool, size_t size);
void *rap_pnalloc(rap_pool_t *pool, size_t size);
void *rap_pcalloc(rap_pool_t *pool, size_t size);
void *rap_pmemalign(rap_pool_t *pool, size_t size, size_t alignment);
rap_int_t rap_pfree(rap_pool_t *pool, void *p);


rap_pool_cleanup_t *rap_pool_cleanup_add(rap_pool_t *p, size_t size);
void rap_pool_run_cleanup_file(rap_pool_t *p, rap_fd_t fd);
void rap_pool_cleanup_file(void *data);
void rap_pool_delete_file(void *data);


#endif /* _RAP_PALLOC_H_INCLUDED_ */
