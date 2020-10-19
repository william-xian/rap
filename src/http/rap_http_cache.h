
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_CACHE_H_INCLUDED_
#define _RAP_HTTP_CACHE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_CACHE_MISS          1
#define RAP_HTTP_CACHE_BYPASS        2
#define RAP_HTTP_CACHE_EXPIRED       3
#define RAP_HTTP_CACHE_STALE         4
#define RAP_HTTP_CACHE_UPDATING      5
#define RAP_HTTP_CACHE_REVALIDATED   6
#define RAP_HTTP_CACHE_HIT           7
#define RAP_HTTP_CACHE_SCARCE        8

#define RAP_HTTP_CACHE_KEY_LEN       16
#define RAP_HTTP_CACHE_ETAG_LEN      128
#define RAP_HTTP_CACHE_VARY_LEN      128

#define RAP_HTTP_CACHE_VERSION       5


typedef struct {
    rap_uint_t                       status;
    time_t                           valid;
} rap_http_cache_valid_t;


typedef struct {
    rap_rbtree_node_t                node;
    rap_queue_t                      queue;

    u_char                           key[RAP_HTTP_CACHE_KEY_LEN
                                         - sizeof(rap_rbtree_key_t)];

    unsigned                         count:20;
    unsigned                         uses:10;
    unsigned                         valid_msec:10;
    unsigned                         error:10;
    unsigned                         exists:1;
    unsigned                         updating:1;
    unsigned                         deleting:1;
    unsigned                         purged:1;
                                     /* 10 unused bits */

    rap_file_uniq_t                  uniq;
    time_t                           expire;
    time_t                           valid_sec;
    size_t                           body_start;
    off_t                            fs_size;
    rap_msec_t                       lock_time;
} rap_http_file_cache_node_t;


struct rap_http_cache_s {
    rap_file_t                       file;
    rap_array_t                      keys;
    uint32_t                         crc32;
    u_char                           key[RAP_HTTP_CACHE_KEY_LEN];
    u_char                           main[RAP_HTTP_CACHE_KEY_LEN];

    rap_file_uniq_t                  uniq;
    time_t                           valid_sec;
    time_t                           updating_sec;
    time_t                           error_sec;
    time_t                           last_modified;
    time_t                           date;

    rap_str_t                        etag;
    rap_str_t                        vary;
    u_char                           variant[RAP_HTTP_CACHE_KEY_LEN];

    size_t                           header_start;
    size_t                           body_start;
    off_t                            length;
    off_t                            fs_size;

    rap_uint_t                       min_uses;
    rap_uint_t                       error;
    rap_uint_t                       valid_msec;
    rap_uint_t                       vary_tag;

    rap_buf_t                       *buf;

    rap_http_file_cache_t           *file_cache;
    rap_http_file_cache_node_t      *node;

#if (RAP_THREADS || RAP_COMPAT)
    rap_thread_task_t               *thread_task;
#endif

    rap_msec_t                       lock_timeout;
    rap_msec_t                       lock_age;
    rap_msec_t                       lock_time;
    rap_msec_t                       wait_time;

    rap_event_t                      wait_event;

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
    rap_uint_t                       version;
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
    u_char                           etag[RAP_HTTP_CACHE_ETAG_LEN];
    u_char                           vary_len;
    u_char                           vary[RAP_HTTP_CACHE_VARY_LEN];
    u_char                           variant[RAP_HTTP_CACHE_KEY_LEN];
} rap_http_file_cache_header_t;


typedef struct {
    rap_rbtree_t                     rbtree;
    rap_rbtree_node_t                sentinel;
    rap_queue_t                      queue;
    rap_atomic_t                     cold;
    rap_atomic_t                     loading;
    off_t                            size;
    rap_uint_t                       count;
    rap_uint_t                       watermark;
} rap_http_file_cache_sh_t;


struct rap_http_file_cache_s {
    rap_http_file_cache_sh_t        *sh;
    rap_slab_pool_t                 *shpool;

    rap_path_t                      *path;

    off_t                            max_size;
    size_t                           bsize;

    time_t                           inactive;

    time_t                           fail_time;

    rap_uint_t                       files;
    rap_uint_t                       loader_files;
    rap_msec_t                       last;
    rap_msec_t                       loader_sleep;
    rap_msec_t                       loader_threshold;

    rap_uint_t                       manager_files;
    rap_msec_t                       manager_sleep;
    rap_msec_t                       manager_threshold;

    rap_shm_zone_t                  *shm_zone;

    rap_uint_t                       use_temp_path;
                                     /* unsigned use_temp_path:1 */
};


rap_int_t rap_http_file_cache_new(rap_http_request_t *r);
rap_int_t rap_http_file_cache_create(rap_http_request_t *r);
void rap_http_file_cache_create_key(rap_http_request_t *r);
rap_int_t rap_http_file_cache_open(rap_http_request_t *r);
rap_int_t rap_http_file_cache_set_header(rap_http_request_t *r, u_char *buf);
void rap_http_file_cache_update(rap_http_request_t *r, rap_temp_file_t *tf);
void rap_http_file_cache_update_header(rap_http_request_t *r);
rap_int_t rap_http_cache_send(rap_http_request_t *);
void rap_http_file_cache_free(rap_http_cache_t *c, rap_temp_file_t *tf);
time_t rap_http_file_cache_valid(rap_array_t *cache_valid, rap_uint_t status);

char *rap_http_file_cache_set_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
char *rap_http_file_cache_valid_set_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


extern rap_str_t  rap_http_cache_status[];


#endif /* _RAP_HTTP_CACHE_H_INCLUDED_ */
