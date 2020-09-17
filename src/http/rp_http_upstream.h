
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HTTP_UPSTREAM_H_INCLUDED_
#define _RP_HTTP_UPSTREAM_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_event_connect.h>
#include <rp_event_pipe.h>
#include <rp_http.h>


#define RP_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define RP_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define RP_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define RP_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define RP_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define RP_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define RP_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define RP_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define RP_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define RP_HTTP_UPSTREAM_FT_HTTP_429        0x00000400
#define RP_HTTP_UPSTREAM_FT_UPDATING        0x00000800
#define RP_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00001000
#define RP_HTTP_UPSTREAM_FT_MAX_WAITING     0x00002000
#define RP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00004000
#define RP_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define RP_HTTP_UPSTREAM_FT_OFF             0x80000000

#define RP_HTTP_UPSTREAM_FT_STATUS          (RP_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |RP_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |RP_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |RP_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |RP_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |RP_HTTP_UPSTREAM_FT_HTTP_404  \
                                             |RP_HTTP_UPSTREAM_FT_HTTP_429)

#define RP_HTTP_UPSTREAM_INVALID_HEADER     40


#define RP_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define RP_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define RP_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define RP_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define RP_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define RP_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define RP_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define RP_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define RP_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    rp_uint_t                       status;
    rp_msec_t                       response_time;
    rp_msec_t                       connect_time;
    rp_msec_t                       header_time;
    rp_msec_t                       queue_time;
    off_t                            response_length;
    off_t                            bytes_received;
    off_t                            bytes_sent;

    rp_str_t                       *peer;
} rp_http_upstream_state_t;


typedef struct {
    rp_hash_t                       headers_in_hash;
    rp_array_t                      upstreams;
                                             /* rp_http_upstream_srv_conf_t */
} rp_http_upstream_main_conf_t;

typedef struct rp_http_upstream_srv_conf_s  rp_http_upstream_srv_conf_t;

typedef rp_int_t (*rp_http_upstream_init_pt)(rp_conf_t *cf,
    rp_http_upstream_srv_conf_t *us);
typedef rp_int_t (*rp_http_upstream_init_peer_pt)(rp_http_request_t *r,
    rp_http_upstream_srv_conf_t *us);


typedef struct {
    rp_http_upstream_init_pt        init_upstream;
    rp_http_upstream_init_peer_pt   init;
    void                            *data;
} rp_http_upstream_peer_t;


typedef struct {
    rp_str_t                        name;
    rp_addr_t                      *addrs;
    rp_uint_t                       naddrs;
    rp_uint_t                       weight;
    rp_uint_t                       max_conns;
    rp_uint_t                       max_fails;
    time_t                           fail_timeout;
    rp_msec_t                       slow_start;
    rp_uint_t                       down;

    unsigned                         backup:1;

    RP_COMPAT_BEGIN(6)
    RP_COMPAT_END
} rp_http_upstream_server_t;


#define RP_HTTP_UPSTREAM_CREATE        0x0001
#define RP_HTTP_UPSTREAM_WEIGHT        0x0002
#define RP_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define RP_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define RP_HTTP_UPSTREAM_DOWN          0x0010
#define RP_HTTP_UPSTREAM_BACKUP        0x0020
#define RP_HTTP_UPSTREAM_MAX_CONNS     0x0100


struct rp_http_upstream_srv_conf_s {
    rp_http_upstream_peer_t         peer;
    void                           **srv_conf;

    rp_array_t                     *servers;  /* rp_http_upstream_server_t */

    rp_uint_t                       flags;
    rp_str_t                        host;
    u_char                          *file_name;
    rp_uint_t                       line;
    in_port_t                        port;
    rp_uint_t                       no_port;  /* unsigned no_port:1 */

#if (RP_HTTP_UPSTREAM_ZONE)
    rp_shm_zone_t                  *shm_zone;
#endif
};


typedef struct {
    rp_addr_t                      *addr;
    rp_http_complex_value_t        *value;
#if (RP_HAVE_TRANSPARENT_PROXY)
    rp_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} rp_http_upstream_local_t;


typedef struct {
    rp_http_upstream_srv_conf_t    *upstream;

    rp_msec_t                       connect_timeout;
    rp_msec_t                       send_timeout;
    rp_msec_t                       read_timeout;
    rp_msec_t                       next_upstream_timeout;

    size_t                           send_lowat;
    size_t                           buffer_size;
    size_t                           limit_rate;

    size_t                           busy_buffers_size;
    size_t                           max_temp_file_size;
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    rp_bufs_t                       bufs;

    rp_uint_t                       ignore_headers;
    rp_uint_t                       next_upstream;
    rp_uint_t                       store_access;
    rp_uint_t                       next_upstream_tries;
    rp_flag_t                       buffering;
    rp_flag_t                       request_buffering;
    rp_flag_t                       pass_request_headers;
    rp_flag_t                       pass_request_body;

    rp_flag_t                       ignore_client_abort;
    rp_flag_t                       intercept_errors;
    rp_flag_t                       cyclic_temp_file;
    rp_flag_t                       force_ranges;

    rp_path_t                      *temp_path;

    rp_hash_t                       hide_headers_hash;
    rp_array_t                     *hide_headers;
    rp_array_t                     *pass_headers;

    rp_http_upstream_local_t       *local;
    rp_flag_t                       socket_keepalive;

#if (RP_HTTP_CACHE)
    rp_shm_zone_t                  *cache_zone;
    rp_http_complex_value_t        *cache_value;

    rp_uint_t                       cache_min_uses;
    rp_uint_t                       cache_use_stale;
    rp_uint_t                       cache_methods;

    off_t                            cache_max_range_offset;

    rp_flag_t                       cache_lock;
    rp_msec_t                       cache_lock_timeout;
    rp_msec_t                       cache_lock_age;

    rp_flag_t                       cache_revalidate;
    rp_flag_t                       cache_convert_head;
    rp_flag_t                       cache_background_update;

    rp_array_t                     *cache_valid;
    rp_array_t                     *cache_bypass;
    rp_array_t                     *cache_purge;
    rp_array_t                     *no_cache;
#endif

    rp_array_t                     *store_lengths;
    rp_array_t                     *store_values;

#if (RP_HTTP_CACHE)
    signed                           cache:2;
#endif
    signed                           store:2;
    unsigned                         intercept_404:1;
    unsigned                         change_buffering:1;
    unsigned                         pass_trailers:1;
    unsigned                         preserve_output:1;

#if (RP_HTTP_SSL || RP_COMPAT)
    rp_ssl_t                       *ssl;
    rp_flag_t                       ssl_session_reuse;

    rp_http_complex_value_t        *ssl_name;
    rp_flag_t                       ssl_server_name;
    rp_flag_t                       ssl_verify;
#endif

    rp_str_t                        module;

    RP_COMPAT_BEGIN(2)
    RP_COMPAT_END
} rp_http_upstream_conf_t;


typedef struct {
    rp_str_t                        name;
    rp_http_header_handler_pt       handler;
    rp_uint_t                       offset;
    rp_http_header_handler_pt       copy_handler;
    rp_uint_t                       conf;
    rp_uint_t                       redirect;  /* unsigned   redirect:1; */
} rp_http_upstream_header_t;


typedef struct {
    rp_list_t                       headers;
    rp_list_t                       trailers;

    rp_uint_t                       status_n;
    rp_str_t                        status_line;

    rp_table_elt_t                 *status;
    rp_table_elt_t                 *date;
    rp_table_elt_t                 *server;
    rp_table_elt_t                 *connection;

    rp_table_elt_t                 *expires;
    rp_table_elt_t                 *etag;
    rp_table_elt_t                 *x_accel_expires;
    rp_table_elt_t                 *x_accel_redirect;
    rp_table_elt_t                 *x_accel_limit_rate;

    rp_table_elt_t                 *content_type;
    rp_table_elt_t                 *content_length;

    rp_table_elt_t                 *last_modified;
    rp_table_elt_t                 *location;
    rp_table_elt_t                 *accept_ranges;
    rp_table_elt_t                 *www_authenticate;
    rp_table_elt_t                 *transfer_encoding;
    rp_table_elt_t                 *vary;

#if (RP_HTTP_GZIP)
    rp_table_elt_t                 *content_encoding;
#endif

    rp_array_t                      cache_control;
    rp_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} rp_http_upstream_headers_in_t;


typedef struct {
    rp_str_t                        host;
    in_port_t                        port;
    rp_uint_t                       no_port; /* unsigned no_port:1 */

    rp_uint_t                       naddrs;
    rp_resolver_addr_t             *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    rp_str_t                        name;

    rp_resolver_ctx_t              *ctx;
} rp_http_upstream_resolved_t;


typedef void (*rp_http_upstream_handler_pt)(rp_http_request_t *r,
    rp_http_upstream_t *u);


struct rp_http_upstream_s {
    rp_http_upstream_handler_pt     read_event_handler;
    rp_http_upstream_handler_pt     write_event_handler;

    rp_peer_connection_t            peer;

    rp_event_pipe_t                *pipe;

    rp_chain_t                     *request_bufs;

    rp_output_chain_ctx_t           output;
    rp_chain_writer_ctx_t           writer;

    rp_http_upstream_conf_t        *conf;
    rp_http_upstream_srv_conf_t    *upstream;
#if (RP_HTTP_CACHE)
    rp_array_t                     *caches;
#endif

    rp_http_upstream_headers_in_t   headers_in;

    rp_http_upstream_resolved_t    *resolved;

    rp_buf_t                        from_client;

    rp_buf_t                        buffer;
    off_t                            length;

    rp_chain_t                     *out_bufs;
    rp_chain_t                     *busy_bufs;
    rp_chain_t                     *free_bufs;

    rp_int_t                      (*input_filter_init)(void *data);
    rp_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;

#if (RP_HTTP_CACHE)
    rp_int_t                      (*create_key)(rp_http_request_t *r);
#endif
    rp_int_t                      (*create_request)(rp_http_request_t *r);
    rp_int_t                      (*reinit_request)(rp_http_request_t *r);
    rp_int_t                      (*process_header)(rp_http_request_t *r);
    void                           (*abort_request)(rp_http_request_t *r);
    void                           (*finalize_request)(rp_http_request_t *r,
                                         rp_int_t rc);
    rp_int_t                      (*rewrite_redirect)(rp_http_request_t *r,
                                         rp_table_elt_t *h, size_t prefix);
    rp_int_t                      (*rewrite_cookie)(rp_http_request_t *r,
                                         rp_table_elt_t *h);

    rp_msec_t                       start_time;

    rp_http_upstream_state_t       *state;

    rp_str_t                        method;
    rp_str_t                        schema;
    rp_str_t                        uri;

#if (RP_HTTP_SSL || RP_COMPAT)
    rp_str_t                        ssl_name;
#endif

    rp_http_cleanup_pt             *cleanup;

    unsigned                         store:1;
    unsigned                         cacheable:1;
    unsigned                         accel:1;
    unsigned                         ssl:1;
#if (RP_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    unsigned                         buffering:1;
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;

    unsigned                         request_sent:1;
    unsigned                         request_body_sent:1;
    unsigned                         request_body_blocked:1;
    unsigned                         header_sent:1;
};


typedef struct {
    rp_uint_t                      status;
    rp_uint_t                      mask;
} rp_http_upstream_next_t;


typedef struct {
    rp_str_t   key;
    rp_str_t   value;
    rp_uint_t  skip_empty;
} rp_http_upstream_param_t;


rp_int_t rp_http_upstream_create(rp_http_request_t *r);
void rp_http_upstream_init(rp_http_request_t *r);
rp_http_upstream_srv_conf_t *rp_http_upstream_add(rp_conf_t *cf,
    rp_url_t *u, rp_uint_t flags);
char *rp_http_upstream_bind_set_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
char *rp_http_upstream_param_set_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
rp_int_t rp_http_upstream_hide_headers_hash(rp_conf_t *cf,
    rp_http_upstream_conf_t *conf, rp_http_upstream_conf_t *prev,
    rp_str_t *default_hide_headers, rp_hash_init_t *hash);


#define rp_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern rp_module_t        rp_http_upstream_module;
extern rp_conf_bitmask_t  rp_http_upstream_cache_method_mask[];
extern rp_conf_bitmask_t  rp_http_upstream_ignore_headers_masks[];


#endif /* _RP_HTTP_UPSTREAM_H_INCLUDED_ */
