
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_UPSTREAM_H_INCLUDED_
#define _RAP_HTTP_UPSTREAM_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_event_connect.h>
#include <rap_event_pipe.h>
#include <rap_http.h>


#define RAP_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define RAP_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define RAP_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define RAP_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define RAP_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define RAP_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define RAP_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define RAP_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define RAP_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define RAP_HTTP_UPSTREAM_FT_HTTP_429        0x00000400
#define RAP_HTTP_UPSTREAM_FT_UPDATING        0x00000800
#define RAP_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00001000
#define RAP_HTTP_UPSTREAM_FT_MAX_WAITING     0x00002000
#define RAP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00004000
#define RAP_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define RAP_HTTP_UPSTREAM_FT_OFF             0x80000000

#define RAP_HTTP_UPSTREAM_FT_STATUS          (RAP_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |RAP_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |RAP_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |RAP_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |RAP_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |RAP_HTTP_UPSTREAM_FT_HTTP_404  \
                                             |RAP_HTTP_UPSTREAM_FT_HTTP_429)

#define RAP_HTTP_UPSTREAM_INVALID_HEADER     40


#define RAP_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define RAP_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define RAP_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define RAP_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define RAP_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define RAP_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define RAP_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define RAP_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define RAP_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    rap_uint_t                       status;
    rap_msec_t                       response_time;
    rap_msec_t                       connect_time;
    rap_msec_t                       header_time;
    rap_msec_t                       queue_time;
    off_t                            response_length;
    off_t                            bytes_received;
    off_t                            bytes_sent;

    rap_str_t                       *peer;
} rap_http_upstream_state_t;


typedef struct {
    rap_hash_t                       headers_in_hash;
    rap_array_t                      upstreams;
                                             /* rap_http_upstream_srv_conf_t */
} rap_http_upstream_main_conf_t;

typedef struct rap_http_upstream_srv_conf_s  rap_http_upstream_srv_conf_t;

typedef rap_int_t (*rap_http_upstream_init_pt)(rap_conf_t *cf,
    rap_http_upstream_srv_conf_t *us);
typedef rap_int_t (*rap_http_upstream_init_peer_pt)(rap_http_request_t *r,
    rap_http_upstream_srv_conf_t *us);


typedef struct {
    rap_http_upstream_init_pt        init_upstream;
    rap_http_upstream_init_peer_pt   init;
    void                            *data;
} rap_http_upstream_peer_t;


typedef struct {
    rap_str_t                        name;
    rap_addr_t                      *addrs;
    rap_uint_t                       naddrs;
    rap_uint_t                       weight;
    rap_uint_t                       max_conns;
    rap_uint_t                       max_fails;
    time_t                           fail_timeout;
    rap_msec_t                       slow_start;
    rap_uint_t                       down;

    unsigned                         backup:1;

    RAP_COMPAT_BEGIN(6)
    RAP_COMPAT_END
} rap_http_upstream_server_t;


#define RAP_HTTP_UPSTREAM_CREATE        0x0001
#define RAP_HTTP_UPSTREAM_WEIGHT        0x0002
#define RAP_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define RAP_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define RAP_HTTP_UPSTREAM_DOWN          0x0010
#define RAP_HTTP_UPSTREAM_BACKUP        0x0020
#define RAP_HTTP_UPSTREAM_MAX_CONNS     0x0100


struct rap_http_upstream_srv_conf_s {
    rap_http_upstream_peer_t         peer;
    void                           **srv_conf;

    rap_array_t                     *servers;  /* rap_http_upstream_server_t */

    rap_uint_t                       flags;
    rap_str_t                        host;
    u_char                          *file_name;
    rap_uint_t                       line;
    in_port_t                        port;
    rap_uint_t                       no_port;  /* unsigned no_port:1 */

#if (RAP_HTTP_UPSTREAM_ZONE)
    rap_shm_zone_t                  *shm_zone;
#endif
};


typedef struct {
    rap_addr_t                      *addr;
    rap_http_complex_value_t        *value;
#if (RAP_HAVE_TRANSPARENT_PROXY)
    rap_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} rap_http_upstream_local_t;


typedef struct {
    rap_http_upstream_srv_conf_t    *upstream;

    rap_msec_t                       connect_timeout;
    rap_msec_t                       send_timeout;
    rap_msec_t                       read_timeout;
    rap_msec_t                       next_upstream_timeout;

    size_t                           send_lowat;
    size_t                           buffer_size;
    size_t                           limit_rate;

    size_t                           busy_buffers_size;
    size_t                           max_temp_file_size;
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    rap_bufs_t                       bufs;

    rap_uint_t                       ignore_headers;
    rap_uint_t                       next_upstream;
    rap_uint_t                       store_access;
    rap_uint_t                       next_upstream_tries;
    rap_flag_t                       buffering;
    rap_flag_t                       request_buffering;
    rap_flag_t                       pass_request_headers;
    rap_flag_t                       pass_request_body;

    rap_flag_t                       ignore_client_abort;
    rap_flag_t                       intercept_errors;
    rap_flag_t                       cyclic_temp_file;
    rap_flag_t                       force_ranges;

    rap_path_t                      *temp_path;

    rap_hash_t                       hide_headers_hash;
    rap_array_t                     *hide_headers;
    rap_array_t                     *pass_headers;

    rap_http_upstream_local_t       *local;
    rap_flag_t                       socket_keepalive;

#if (RAP_HTTP_CACHE)
    rap_shm_zone_t                  *cache_zone;
    rap_http_complex_value_t        *cache_value;

    rap_uint_t                       cache_min_uses;
    rap_uint_t                       cache_use_stale;
    rap_uint_t                       cache_methods;

    off_t                            cache_max_range_offset;

    rap_flag_t                       cache_lock;
    rap_msec_t                       cache_lock_timeout;
    rap_msec_t                       cache_lock_age;

    rap_flag_t                       cache_revalidate;
    rap_flag_t                       cache_convert_head;
    rap_flag_t                       cache_background_update;

    rap_array_t                     *cache_valid;
    rap_array_t                     *cache_bypass;
    rap_array_t                     *cache_purge;
    rap_array_t                     *no_cache;
#endif

    rap_array_t                     *store_lengths;
    rap_array_t                     *store_values;

#if (RAP_HTTP_CACHE)
    signed                           cache:2;
#endif
    signed                           store:2;
    unsigned                         intercept_404:1;
    unsigned                         change_buffering:1;
    unsigned                         pass_trailers:1;
    unsigned                         preserve_output:1;

#if (RAP_HTTP_SSL || RAP_COMPAT)
    rap_ssl_t                       *ssl;
    rap_flag_t                       ssl_session_reuse;

    rap_http_complex_value_t        *ssl_name;
    rap_flag_t                       ssl_server_name;
    rap_flag_t                       ssl_verify;
#endif

    rap_str_t                        module;

    RAP_COMPAT_BEGIN(2)
    RAP_COMPAT_END
} rap_http_upstream_conf_t;


typedef struct {
    rap_str_t                        name;
    rap_http_header_handler_pt       handler;
    rap_uint_t                       offset;
    rap_http_header_handler_pt       copy_handler;
    rap_uint_t                       conf;
    rap_uint_t                       redirect;  /* unsigned   redirect:1; */
} rap_http_upstream_header_t;


typedef struct {
    rap_list_t                       headers;
    rap_list_t                       trailers;

    rap_uint_t                       status_n;
    rap_str_t                        status_line;

    rap_table_elt_t                 *status;
    rap_table_elt_t                 *date;
    rap_table_elt_t                 *server;
    rap_table_elt_t                 *connection;

    rap_table_elt_t                 *expires;
    rap_table_elt_t                 *etag;
    rap_table_elt_t                 *x_accel_expires;
    rap_table_elt_t                 *x_accel_redirect;
    rap_table_elt_t                 *x_accel_limit_rate;

    rap_table_elt_t                 *content_type;
    rap_table_elt_t                 *content_length;

    rap_table_elt_t                 *last_modified;
    rap_table_elt_t                 *location;
    rap_table_elt_t                 *accept_ranges;
    rap_table_elt_t                 *www_authenticate;
    rap_table_elt_t                 *transfer_encoding;
    rap_table_elt_t                 *vary;

#if (RAP_HTTP_GZIP)
    rap_table_elt_t                 *content_encoding;
#endif

    rap_array_t                      cache_control;
    rap_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} rap_http_upstream_headers_in_t;


typedef struct {
    rap_str_t                        host;
    in_port_t                        port;
    rap_uint_t                       no_port; /* unsigned no_port:1 */

    rap_uint_t                       naddrs;
    rap_resolver_addr_t             *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    rap_str_t                        name;

    rap_resolver_ctx_t              *ctx;
} rap_http_upstream_resolved_t;


typedef void (*rap_http_upstream_handler_pt)(rap_http_request_t *r,
    rap_http_upstream_t *u);


struct rap_http_upstream_s {
    rap_http_upstream_handler_pt     read_event_handler;
    rap_http_upstream_handler_pt     write_event_handler;

    rap_peer_connection_t            peer;

    rap_event_pipe_t                *pipe;

    rap_chain_t                     *request_bufs;

    rap_output_chain_ctx_t           output;
    rap_chain_writer_ctx_t           writer;

    rap_http_upstream_conf_t        *conf;
    rap_http_upstream_srv_conf_t    *upstream;
#if (RAP_HTTP_CACHE)
    rap_array_t                     *caches;
#endif

    rap_http_upstream_headers_in_t   headers_in;

    rap_http_upstream_resolved_t    *resolved;

    rap_buf_t                        from_client;

    rap_buf_t                        buffer;
    off_t                            length;

    rap_chain_t                     *out_bufs;
    rap_chain_t                     *busy_bufs;
    rap_chain_t                     *free_bufs;

    rap_int_t                      (*input_filter_init)(void *data);
    rap_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;

#if (RAP_HTTP_CACHE)
    rap_int_t                      (*create_key)(rap_http_request_t *r);
#endif
    rap_int_t                      (*create_request)(rap_http_request_t *r);
    rap_int_t                      (*reinit_request)(rap_http_request_t *r);
    rap_int_t                      (*process_header)(rap_http_request_t *r);
    void                           (*abort_request)(rap_http_request_t *r);
    void                           (*finalize_request)(rap_http_request_t *r,
                                         rap_int_t rc);
    rap_int_t                      (*rewrite_redirect)(rap_http_request_t *r,
                                         rap_table_elt_t *h, size_t prefix);
    rap_int_t                      (*rewrite_cookie)(rap_http_request_t *r,
                                         rap_table_elt_t *h);

    rap_msec_t                       start_time;

    rap_http_upstream_state_t       *state;

    rap_str_t                        method;
    rap_str_t                        schema;
    rap_str_t                        uri;

#if (RAP_HTTP_SSL || RAP_COMPAT)
    rap_str_t                        ssl_name;
#endif

    rap_http_cleanup_pt             *cleanup;

    unsigned                         store:1;
    unsigned                         cacheable:1;
    unsigned                         accel:1;
    unsigned                         ssl:1;
#if (RAP_HTTP_CACHE)
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
    rap_uint_t                      status;
    rap_uint_t                      mask;
} rap_http_upstream_next_t;


typedef struct {
    rap_str_t   key;
    rap_str_t   value;
    rap_uint_t  skip_empty;
} rap_http_upstream_param_t;


rap_int_t rap_http_upstream_create(rap_http_request_t *r);
void rap_http_upstream_init(rap_http_request_t *r);
rap_http_upstream_srv_conf_t *rap_http_upstream_add(rap_conf_t *cf,
    rap_url_t *u, rap_uint_t flags);
char *rap_http_upstream_bind_set_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
char *rap_http_upstream_param_set_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
rap_int_t rap_http_upstream_hide_headers_hash(rap_conf_t *cf,
    rap_http_upstream_conf_t *conf, rap_http_upstream_conf_t *prev,
    rap_str_t *default_hide_headers, rap_hash_init_t *hash);


#define rap_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern rap_module_t        rap_http_upstream_module;
extern rap_conf_bitmask_t  rap_http_upstream_cache_method_mask[];
extern rap_conf_bitmask_t  rap_http_upstream_ignore_headers_masks[];


#endif /* _RAP_HTTP_UPSTREAM_H_INCLUDED_ */
