
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_HTTP_CORE_H_INCLUDED_
#define _RAP_HTTP_CORE_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>

#if (RAP_THREADS)
#include <rap_thread_pool.h>
#elif (RAP_COMPAT)
typedef struct rap_thread_pool_s  rap_thread_pool_t;
#endif


#define RAP_HTTP_GZIP_PROXIED_OFF       0x0002
#define RAP_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define RAP_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define RAP_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define RAP_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define RAP_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define RAP_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define RAP_HTTP_GZIP_PROXIED_AUTH      0x0100
#define RAP_HTTP_GZIP_PROXIED_ANY       0x0200


#define RAP_HTTP_AIO_OFF                0
#define RAP_HTTP_AIO_ON                 1
#define RAP_HTTP_AIO_THREADS            2


#define RAP_HTTP_SATISFY_ALL            0
#define RAP_HTTP_SATISFY_ANY            1


#define RAP_HTTP_LINGERING_OFF          0
#define RAP_HTTP_LINGERING_ON           1
#define RAP_HTTP_LINGERING_ALWAYS       2


#define RAP_HTTP_IMS_OFF                0
#define RAP_HTTP_IMS_EXACT              1
#define RAP_HTTP_IMS_BEFORE             2


#define RAP_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define RAP_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define RAP_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


#define RAP_HTTP_SERVER_TOKENS_OFF      0
#define RAP_HTTP_SERVER_TOKENS_ON       1
#define RAP_HTTP_SERVER_TOKENS_BUILD    2


typedef struct rap_http_location_tree_node_s  rap_http_location_tree_node_t;
typedef struct rap_http_core_loc_conf_s  rap_http_core_loc_conf_t;


typedef struct {
    struct sockaddr           *sockaddr;
    socklen_t                  socklen;
    rap_str_t                  addr_text;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
    unsigned                   ssl:1;
    unsigned                   http2:1;
#if (RAP_HAVE_INET6)
    unsigned                   ipv6only:1;
#endif
    unsigned                   deferred_accept:1;
    unsigned                   reuseport:1;
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
#if (RAP_HAVE_SETFIB)
    int                        setfib;
#endif
#if (RAP_HAVE_TCP_FASTOPEN)
    int                        fastopen;
#endif
#if (RAP_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (RAP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
} rap_http_listen_opt_t;


typedef enum {
    RAP_HTTP_POST_READ_PHASE = 0,

    RAP_HTTP_SERVER_REWRITE_PHASE,

    RAP_HTTP_FIND_CONFIG_PHASE,
    RAP_HTTP_REWRITE_PHASE,
    RAP_HTTP_POST_REWRITE_PHASE,

    RAP_HTTP_PREACCESS_PHASE,

    RAP_HTTP_ACCESS_PHASE,
    RAP_HTTP_POST_ACCESS_PHASE,

    RAP_HTTP_PRECONTENT_PHASE,

    RAP_HTTP_CONTENT_PHASE,

    RAP_HTTP_LOG_PHASE
} rap_http_phases;

typedef struct rap_http_phase_handler_s  rap_http_phase_handler_t;

typedef rap_int_t (*rap_http_phase_handler_pt)(rap_http_request_t *r,
    rap_http_phase_handler_t *ph);

struct rap_http_phase_handler_s {
    rap_http_phase_handler_pt  checker;
    rap_http_handler_pt        handler;
    rap_uint_t                 next;
};


typedef struct {
    rap_http_phase_handler_t  *handlers;
    rap_uint_t                 server_rewrite_index;
    rap_uint_t                 location_rewrite_index;
} rap_http_phase_engine_t;


typedef struct {
    rap_array_t                handlers;
} rap_http_phase_t;


typedef struct {
    rap_array_t                servers;         /* rap_http_core_srv_conf_t */

    rap_http_phase_engine_t    phase_engine;

    rap_hash_t                 headers_in_hash;

    rap_hash_t                 variables_hash;

    rap_array_t                variables;         /* rap_http_variable_t */
    rap_array_t                prefix_variables;  /* rap_http_variable_t */
    rap_uint_t                 ncaptures;

    rap_uint_t                 server_names_hash_max_size;
    rap_uint_t                 server_names_hash_bucket_size;

    rap_uint_t                 variables_hash_max_size;
    rap_uint_t                 variables_hash_bucket_size;

    rap_hash_keys_arrays_t    *variables_keys;

    rap_array_t               *ports;

    rap_http_phase_t           phases[RAP_HTTP_LOG_PHASE + 1];
} rap_http_core_main_conf_t;


typedef struct {
    /* array of the rap_http_server_name_t, "server_name" directive */
    rap_array_t                 server_names;

    /* server ctx */
    rap_http_conf_ctx_t        *ctx;

    u_char                     *file_name;
    rap_uint_t                  line;

    rap_str_t                   server_name;

    size_t                      connection_pool_size;
    size_t                      request_pool_size;
    size_t                      client_header_buffer_size;

    rap_bufs_t                  large_client_header_buffers;

    rap_msec_t                  client_header_timeout;

    rap_flag_t                  ignore_invalid_headers;
    rap_flag_t                  merge_slashes;
    rap_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (RAP_PCRE)
    unsigned                    captures:1;
#endif

    rap_http_core_loc_conf_t  **named_locations;
} rap_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
#if (RAP_PCRE)
    rap_http_regex_t          *regex;
#endif
    rap_http_core_srv_conf_t  *server;   /* virtual name server conf */
    rap_str_t                  name;
} rap_http_server_name_t;


typedef struct {
    rap_hash_combined_t        names;

    rap_uint_t                 nregex;
    rap_http_server_name_t    *regex;
} rap_http_virtual_names_t;


struct rap_http_addr_conf_s {
    /* the default server configuration for this address:port */
    rap_http_core_srv_conf_t  *default_server;

    rap_http_virtual_names_t  *virtual_names;

    unsigned                   ssl:1;
    unsigned                   http2:1;
    unsigned                   proxy_protocol:1;
};


typedef struct {
    in_addr_t                  addr;
    rap_http_addr_conf_t       conf;
} rap_http_in_addr_t;


#if (RAP_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    rap_http_addr_conf_t       conf;
} rap_http_in6_addr_t;

#endif


typedef struct {
    /* rap_http_in_addr_t or rap_http_in6_addr_t */
    void                      *addrs;
    rap_uint_t                 naddrs;
} rap_http_port_t;


typedef struct {
    rap_int_t                  family;
    in_port_t                  port;
    rap_array_t                addrs;     /* array of rap_http_conf_addr_t */
} rap_http_conf_port_t;


typedef struct {
    rap_http_listen_opt_t      opt;

    rap_hash_t                 hash;
    rap_hash_wildcard_t       *wc_head;
    rap_hash_wildcard_t       *wc_tail;

#if (RAP_PCRE)
    rap_uint_t                 nregex;
    rap_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    rap_http_core_srv_conf_t  *default_server;
    rap_array_t                servers;  /* array of rap_http_core_srv_conf_t */
} rap_http_conf_addr_t;


typedef struct {
    rap_int_t                  status;
    rap_int_t                  overwrite;
    rap_http_complex_value_t   value;
    rap_str_t                  args;
} rap_http_err_page_t;


struct rap_http_core_loc_conf_s {
    rap_str_t     name;          /* location name */

#if (RAP_PCRE)
    rap_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (RAP_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
    unsigned      gzip_disable_degradation:2;
#endif

    rap_http_location_tree_node_t   *static_locations;
#if (RAP_PCRE)
    rap_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    rap_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    rap_str_t     root;                    /* root, alias */
    rap_str_t     post_action;

    rap_array_t  *root_lengths;
    rap_array_t  *root_values;

    rap_array_t  *types;
    rap_hash_t    types_hash;
    rap_str_t     default_type;

    off_t         client_max_body_size;    /* client_max_body_size */
    off_t         directio;                /* directio */
    off_t         directio_alignment;      /* directio_alignment */

    size_t        client_body_buffer_size; /* client_body_buffer_size */
    size_t        send_lowat;              /* send_lowat */
    size_t        postpone_output;         /* postpone_output */
    size_t        sendfile_max_chunk;      /* sendfile_max_chunk */
    size_t        read_ahead;              /* read_ahead */
    size_t        subrequest_output_buffer_size;
                                           /* subrequest_output_buffer_size */

    rap_http_complex_value_t  *limit_rate; /* limit_rate */
    rap_http_complex_value_t  *limit_rate_after; /* limit_rate_after */

    rap_msec_t    client_body_timeout;     /* client_body_timeout */
    rap_msec_t    send_timeout;            /* send_timeout */
    rap_msec_t    keepalive_timeout;       /* keepalive_timeout */
    rap_msec_t    lingering_time;          /* lingering_time */
    rap_msec_t    lingering_timeout;       /* lingering_timeout */
    rap_msec_t    resolver_timeout;        /* resolver_timeout */
    rap_msec_t    auth_delay;              /* auth_delay */

    rap_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    rap_uint_t    keepalive_requests;      /* keepalive_requests */
    rap_uint_t    keepalive_disable;       /* keepalive_disable */
    rap_uint_t    satisfy;                 /* satisfy */
    rap_uint_t    lingering_close;         /* lingering_close */
    rap_uint_t    if_modified_since;       /* if_modified_since */
    rap_uint_t    max_ranges;              /* max_ranges */
    rap_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    rap_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    rap_flag_t    internal;                /* internal */
    rap_flag_t    sendfile;                /* sendfile */
    rap_flag_t    aio;                     /* aio */
    rap_flag_t    aio_write;               /* aio_write */
    rap_flag_t    tcp_nopush;              /* tcp_nopush */
    rap_flag_t    tcp_nodelay;             /* tcp_nodelay */
    rap_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    rap_flag_t    absolute_redirect;       /* absolute_redirect */
    rap_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    rap_flag_t    port_in_redirect;        /* port_in_redirect */
    rap_flag_t    msie_padding;            /* msie_padding */
    rap_flag_t    msie_refresh;            /* msie_refresh */
    rap_flag_t    log_not_found;           /* log_not_found */
    rap_flag_t    log_subrequest;          /* log_subrequest */
    rap_flag_t    recursive_error_pages;   /* recursive_error_pages */
    rap_uint_t    server_tokens;           /* server_tokens */
    rap_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    rap_flag_t    etag;                    /* etag */

#if (RAP_HTTP_GZIP)
    rap_flag_t    gzip_vary;               /* gzip_vary */

    rap_uint_t    gzip_http_version;       /* gzip_http_version */
    rap_uint_t    gzip_proxied;            /* gzip_proxied */

#if (RAP_PCRE)
    rap_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (RAP_THREADS || RAP_COMPAT)
    rap_thread_pool_t         *thread_pool;
    rap_http_complex_value_t  *thread_pool_value;
#endif

#if (RAP_HAVE_OPENAT)
    rap_uint_t    disable_symlinks;        /* disable_symlinks */
    rap_http_complex_value_t  *disable_symlinks_from;
#endif

    rap_array_t  *error_pages;             /* error_page */

    rap_path_t   *client_body_temp_path;   /* client_body_temp_path */

    rap_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    rap_uint_t    open_file_cache_min_uses;
    rap_flag_t    open_file_cache_errors;
    rap_flag_t    open_file_cache_events;

    rap_log_t    *error_log;

    rap_uint_t    types_hash_max_size;
    rap_uint_t    types_hash_bucket_size;

    rap_queue_t  *locations;

#if 0
    rap_http_core_loc_conf_t  *prev_location;
#endif
};


typedef struct {
    rap_queue_t                      queue;
    rap_http_core_loc_conf_t        *exact;
    rap_http_core_loc_conf_t        *inclusive;
    rap_str_t                       *name;
    u_char                          *file_name;
    rap_uint_t                       line;
    rap_queue_t                      list;
} rap_http_location_queue_t;


struct rap_http_location_tree_node_s {
    rap_http_location_tree_node_t   *left;
    rap_http_location_tree_node_t   *right;
    rap_http_location_tree_node_t   *tree;

    rap_http_core_loc_conf_t        *exact;
    rap_http_core_loc_conf_t        *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};


void rap_http_core_run_phases(rap_http_request_t *r);
rap_int_t rap_http_core_generic_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph);
rap_int_t rap_http_core_rewrite_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph);
rap_int_t rap_http_core_find_config_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph);
rap_int_t rap_http_core_post_rewrite_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph);
rap_int_t rap_http_core_access_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph);
rap_int_t rap_http_core_post_access_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph);
rap_int_t rap_http_core_content_phase(rap_http_request_t *r,
    rap_http_phase_handler_t *ph);


void *rap_http_test_content_type(rap_http_request_t *r, rap_hash_t *types_hash);
rap_int_t rap_http_set_content_type(rap_http_request_t *r);
void rap_http_set_exten(rap_http_request_t *r);
rap_int_t rap_http_set_etag(rap_http_request_t *r);
void rap_http_weak_etag(rap_http_request_t *r);
rap_int_t rap_http_send_response(rap_http_request_t *r, rap_uint_t status,
    rap_str_t *ct, rap_http_complex_value_t *cv);
u_char *rap_http_map_uri_to_path(rap_http_request_t *r, rap_str_t *name,
    size_t *root_length, size_t reserved);
rap_int_t rap_http_auth_basic_user(rap_http_request_t *r);
#if (RAP_HTTP_GZIP)
rap_int_t rap_http_gzip_ok(rap_http_request_t *r);
#endif


rap_int_t rap_http_subrequest(rap_http_request_t *r,
    rap_str_t *uri, rap_str_t *args, rap_http_request_t **sr,
    rap_http_post_subrequest_t *psr, rap_uint_t flags);
rap_int_t rap_http_internal_redirect(rap_http_request_t *r,
    rap_str_t *uri, rap_str_t *args);
rap_int_t rap_http_named_location(rap_http_request_t *r, rap_str_t *name);


rap_http_cleanup_t *rap_http_cleanup_add(rap_http_request_t *r, size_t size);


typedef rap_int_t (*rap_http_output_header_filter_pt)(rap_http_request_t *r);
typedef rap_int_t (*rap_http_output_body_filter_pt)
    (rap_http_request_t *r, rap_chain_t *chain);
typedef rap_int_t (*rap_http_request_body_filter_pt)
    (rap_http_request_t *r, rap_chain_t *chain);


rap_int_t rap_http_output_filter(rap_http_request_t *r, rap_chain_t *chain);
rap_int_t rap_http_write_filter(rap_http_request_t *r, rap_chain_t *chain);
rap_int_t rap_http_request_body_save_filter(rap_http_request_t *r,
    rap_chain_t *chain);


rap_int_t rap_http_set_disable_symlinks(rap_http_request_t *r,
    rap_http_core_loc_conf_t *clcf, rap_str_t *path, rap_open_file_info_t *of);

rap_int_t rap_http_get_forwarded_addr(rap_http_request_t *r, rap_addr_t *addr,
    rap_array_t *headers, rap_str_t *value, rap_array_t *proxies,
    int recursive);


extern rap_module_t  rap_http_core_module;

extern rap_uint_t rap_http_max_module;

extern rap_str_t  rap_http_core_get_method;


#define rap_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

#define rap_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define rap_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define rap_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

#define rap_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _RAP_HTTP_CORE_H_INCLUDED_ */
