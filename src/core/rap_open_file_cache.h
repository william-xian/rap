
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#ifndef _RAP_OPEN_FILE_CACHE_H_INCLUDED_
#define _RAP_OPEN_FILE_CACHE_H_INCLUDED_


#define RAP_OPEN_FILE_DIRECTIO_OFF  RAP_MAX_OFF_T_VALUE


typedef struct {
    rap_fd_t                 fd;
    rap_file_uniq_t          uniq;
    time_t                   mtime;
    off_t                    size;
    off_t                    fs_size;
    off_t                    directio;
    size_t                   read_ahead;

    rap_err_t                err;
    char                    *failed;

    time_t                   valid;

    rap_uint_t               min_uses;

#if (RAP_HAVE_OPENAT)
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
} rap_open_file_info_t;


typedef struct rap_cached_open_file_s  rap_cached_open_file_t;

struct rap_cached_open_file_s {
    rap_rbtree_node_t        node;
    rap_queue_t              queue;

    u_char                  *name;
    time_t                   created;
    time_t                   accessed;

    rap_fd_t                 fd;
    rap_file_uniq_t          uniq;
    time_t                   mtime;
    off_t                    size;
    rap_err_t                err;

    uint32_t                 uses;

#if (RAP_HAVE_OPENAT)
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

    rap_event_t             *event;
};


typedef struct {
    rap_rbtree_t             rbtree;
    rap_rbtree_node_t        sentinel;
    rap_queue_t              expire_queue;

    rap_uint_t               current;
    rap_uint_t               max;
    time_t                   inactive;
} rap_open_file_cache_t;


typedef struct {
    rap_open_file_cache_t   *cache;
    rap_cached_open_file_t  *file;
    rap_uint_t               min_uses;
    rap_log_t               *log;
} rap_open_file_cache_cleanup_t;


typedef struct {

    /* rap_connection_t stub to allow use c->fd as event ident */
    void                    *data;
    rap_event_t             *read;
    rap_event_t             *write;
    rap_fd_t                 fd;

    rap_cached_open_file_t  *file;
    rap_open_file_cache_t   *cache;
} rap_open_file_cache_event_t;


rap_open_file_cache_t *rap_open_file_cache_init(rap_pool_t *pool,
    rap_uint_t max, time_t inactive);
rap_int_t rap_open_cached_file(rap_open_file_cache_t *cache, rap_str_t *name,
    rap_open_file_info_t *of, rap_pool_t *pool);


#endif /* _RAP_OPEN_FILE_CACHE_H_INCLUDED_ */
