
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HTTP_CACHE_H_INCLUDED_
#define _RP_HTTP_CACHE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_CACHE_MISS          1
#define RP_HTTP_CACHE_BYPASS        2
#define RP_HTTP_CACHE_EXPIRED       3
#define RP_HTTP_CACHE_STALE         4
#define RP_HTTP_CACHE_UPDATING      5
#define RP_HTTP_CACHE_REVALIDATED   6
#define RP_HTTP_CACHE_HIT           7
#define RP_HTTP_CACHE_SCARCE        8

#define RP_HTTP_CACHE_KEY_LEN       16
#define RP_HTTP_CACHE_ETAG_LEN      128
#define RP_HTTP_CACHE_VARY_LEN      128

#define RP_HTTP_CACHE_VERSION       5


typedef struct {
    rp_uint_t                       status;
    time_t                           valid;
} rp_http_cache_valid_t;


typedef struct {
    rp_rbtree_node_t                node;
    rp_queue_t                      queue;

    u_char                           key[RP_HTTP_CACHE_KEY_LEN
                                         - sizeof(rp_rbtree_key_t)];

    unsigned                         count:20;
    unsigned                         uses:10;
    unsigned                         valid_msec:10;
    unsigned                         error:10;
    unsigned                         exists:1;
    unsigned                         updating:1;
    unsigned                         deleting:1;
    unsigned                         purged:1;
                                     /* 10 unused bits */

    rp_file_uniq_t                  uniq;
    time_t                           expire;
    time_t                           valid_sec;
    size_t                           body_start;
    off_t                            fs_size;
    rp_msec_t                       lock_time;
} rp_http_file_cache_node_t;


struct rp_http_cache_s {
    rp_file_t                       file;
    rp_array_t                      keys;
    uint32_t                         crc32;
    u_char                           key[RP_HTTP_CACHE_KEY_LEN];
    u_char                           main[RP_HTTP_CACHE_KEY_LEN];

    rp_file_uniq_t                  uniq;
    time_t                           valid_sec;
    time_t                           updating_sec;
    time_t                           error_sec;
    time_t                           last_modified;
    time_t                           date;

    rp_str_t                        etag;
    rp_str_t                        vary;
    u_char                           variant[RP_HTTP_CACHE_KEY_LEN];

    size_t                           header_start;
    size_t                           body_start;
    off_t                            length;
    off_t                            fs_size;

    rp_uint_t                       min_uses;
    rp_uint_t                       error;
    rp_uint_t                       valid_msec;
    rp_uint_t                       vary_tag;

    rp_buf_t                       *buf;

    rp_http_file_cache_t           *file_cache;
    rp_http_file_cache_node_t      *node;

#if (RP_THREADS || RP_COMPAT)
    rp_thread_task_t               *thread_task;
#endif

    rp_msec_t                       lock_timeout;
    rp_msec_t                       lock_age;
    rp_msec_t                       lock_time;
    rp_msec_t                       wait_time;

    rp_event_t                      wait_event;

    unsigned                         lock:1;
    unsigned                         waiting:1;

    unsigned                         updated:1;
    unsigned                         updating:1;
    unsigned                         exists:1;
    unsigned                         temp_file:1;
    unsigned                         purged:1;
    unsigned                         reading:1;
    unsigned                         secondary:1;
    unsigned                         background:1;

    unsigned                         stale_updating:1;
    unsigned                         stale_error:1;
};


typedef struct {
    rp_uint_t                       version;
    time_t                           valid_sec;
    time_t                           updating_sec;
    time_t                           error_sec;
    time_t                           last_modified;
    time_t                           date;
    uint32_t                         crc32;
    u_short                          valid_msec;
    u_short                          header_start;
    u_short                          body_start;
    u_char                           etag_len;
    u_char                           etag[RP_HTTP_CACHE_ETAG_LEN];
    u_char                           vary_len;
    u_char                           vary[RP_HTTP_CACHE_VARY_LEN];
    u_char                           variant[RP_HTTP_CACHE_KEY_LEN];
} rp_http_file_cache_header_t;


typedef struct {
    rp_rbtree_t                     rbtree;
    rp_rbtree_node_t                sentinel;
    rp_queue_t                      queue;
    rp_atomic_t                     cold;
    rp_atomic_t                     loading;
    off_t                            size;
    rp_uint_t                       count;
    rp_uint_t                       watermark;
} rp_http_file_cache_sh_t;


struct rp_http_file_cache_s {
    rp_http_file_cache_sh_t        *sh;
    rp_slab_pool_t                 *shpool;

    rp_path_t                      *path;

    off_t                            max_size;
    size_t                           bsize;

    time_t                           inactive;

    time_t                           fail_time;

    rp_uint_t                       files;
    rp_uint_t                       loader_files;
    rp_msec_t                       last;
    rp_msec_t                       loader_sleep;
    rp_msec_t                       loader_threshold;

    rp_uint_t                       manager_files;
    rp_msec_t                       manager_sleep;
    rp_msec_t                       manager_threshold;

    rp_shm_zone_t                  *shm_zone;

    rp_uint_t                       use_temp_path;
                                     /* unsigned use_temp_path:1 */
};


rp_int_t rp_http_file_cache_new(rp_http_request_t *r);
rp_int_t rp_http_file_cache_create(rp_http_request_t *r);
void rp_http_file_cache_create_key(rp_http_request_t *r);
rp_int_t rp_http_file_cache_open(rp_http_request_t *r);
rp_int_t rp_http_file_cache_set_header(rp_http_request_t *r, u_char *buf);
void rp_http_file_cache_update(rp_http_request_t *r, rp_temp_file_t *tf);
void rp_http_file_cache_update_header(rp_http_request_t *r);
rp_int_t rp_http_cache_send(rp_http_request_t *);
void rp_http_file_cache_free(rp_http_cache_t *c, rp_temp_file_t *tf);
time_t rp_http_file_cache_valid(rp_array_t *cache_valid, rp_uint_t status);

char *rp_http_file_cache_set_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
char *rp_http_file_cache_valid_set_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


extern rp_str_t  rp_http_cache_status[];


#endif /* _RP_HTTP_CACHE_H_INCLUDED_ */
