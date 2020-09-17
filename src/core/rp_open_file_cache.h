
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#ifndef _RP_OPEN_FILE_CACHE_H_INCLUDED_
#define _RP_OPEN_FILE_CACHE_H_INCLUDED_


#define RP_OPEN_FILE_DIRECTIO_OFF  RP_MAX_OFF_T_VALUE


typedef struct {
    rp_fd_t                 fd;
    rp_file_uniq_t          uniq;
    time_t                   mtime;
    off_t                    size;
    off_t                    fs_size;
    off_t                    directio;
    size_t                   read_ahead;

    rp_err_t                err;
    char                    *failed;

    time_t                   valid;

    rp_uint_t               min_uses;

#if (RP_HAVE_OPENAT)
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif

    unsigned                 test_dir:1;
    unsigned                 test_only:1;
    unsigned                 log:1;
    unsigned                 errors:1;
    unsigned                 events:1;

    unsigned                 is_dir:1;
    unsigned                 is_file:1;
    unsigned                 is_link:1;
    unsigned                 is_exec:1;
    unsigned                 is_directio:1;
} rp_open_file_info_t;


typedef struct rp_cached_open_file_s  rp_cached_open_file_t;

struct rp_cached_open_file_s {
    rp_rbtree_node_t        node;
    rp_queue_t              queue;

    u_char                  *name;
    time_t                   created;
    time_t                   accessed;

    rp_fd_t                 fd;
    rp_file_uniq_t          uniq;
    time_t                   mtime;
    off_t                    size;
    rp_err_t                err;

    uint32_t                 uses;

#if (RP_HAVE_OPENAT)
    size_t                   disable_symlinks_from;
    unsigned                 disable_symlinks:2;
#endif

    unsigned                 count:24;
    unsigned                 close:1;
    unsigned                 use_event:1;

    unsigned                 is_dir:1;
    unsigned                 is_file:1;
    unsigned                 is_link:1;
    unsigned                 is_exec:1;
    unsigned                 is_directio:1;

    rp_event_t             *event;
};


typedef struct {
    rp_rbtree_t             rbtree;
    rp_rbtree_node_t        sentinel;
    rp_queue_t              expire_queue;

    rp_uint_t               current;
    rp_uint_t               max;
    time_t                   inactive;
} rp_open_file_cache_t;


typedef struct {
    rp_open_file_cache_t   *cache;
    rp_cached_open_file_t  *file;
    rp_uint_t               min_uses;
    rp_log_t               *log;
} rp_open_file_cache_cleanup_t;


typedef struct {

    /* rp_connection_t stub to allow use c->fd as event ident */
    void                    *data;
    rp_event_t             *read;
    rp_event_t             *write;
    rp_fd_t                 fd;

    rp_cached_open_file_t  *file;
    rp_open_file_cache_t   *cache;
} rp_open_file_cache_event_t;


rp_open_file_cache_t *rp_open_file_cache_init(rp_pool_t *pool,
    rp_uint_t max, time_t inactive);
rp_int_t rp_open_cached_file(rp_open_file_cache_t *cache, rp_str_t *name,
    rp_open_file_info_t *of, rp_pool_t *pool);


#endif /* _RP_OPEN_FILE_CACHE_H_INCLUDED_ */
