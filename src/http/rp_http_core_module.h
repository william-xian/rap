
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_HTTP_CORE_H_INCLUDED_
#define _RP_HTTP_CORE_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>

#if (RP_THREADS)
#include <rp_thread_pool.h>
#elif (RP_COMPAT)
typedef struct rp_thread_pool_s  rp_thread_pool_t;
#endif


#define RP_HTTP_GZIP_PROXIED_OFF       0x0002
#define RP_HTTP_GZIP_PROXIED_EXPIRED   0x0004
#define RP_HTTP_GZIP_PROXIED_NO_CACHE  0x0008
#define RP_HTTP_GZIP_PROXIED_NO_STORE  0x0010
#define RP_HTTP_GZIP_PROXIED_PRIVATE   0x0020
#define RP_HTTP_GZIP_PROXIED_NO_LM     0x0040
#define RP_HTTP_GZIP_PROXIED_NO_ETAG   0x0080
#define RP_HTTP_GZIP_PROXIED_AUTH      0x0100
#define RP_HTTP_GZIP_PROXIED_ANY       0x0200


#define RP_HTTP_AIO_OFF                0
#define RP_HTTP_AIO_ON                 1
#define RP_HTTP_AIO_THREADS            2


#define RP_HTTP_SATISFY_ALL            0
#define RP_HTTP_SATISFY_ANY            1


#define RP_HTTP_LINGERING_OFF          0
#define RP_HTTP_LINGERING_ON           1
#define RP_HTTP_LINGERING_ALWAYS       2


#define RP_HTTP_IMS_OFF                0
#define RP_HTTP_IMS_EXACT              1
#define RP_HTTP_IMS_BEFORE             2


#define RP_HTTP_KEEPALIVE_DISABLE_NONE    0x0002
#define RP_HTTP_KEEPALIVE_DISABLE_MSIE6   0x0004
#define RP_HTTP_KEEPALIVE_DISABLE_SAFARI  0x0008


#define RP_HTTP_SERVER_TOKENS_OFF      0
#define RP_HTTP_SERVER_TOKENS_ON       1
#define RP_HTTP_SERVER_TOKENS_BUILD    2


typedef struct rp_http_location_tree_node_s  rp_http_location_tree_node_t;
typedef struct rp_http_core_loc_conf_s  rp_http_core_loc_conf_t;


typedef struct {
    struct sockaddr           *sockaddr;
    socklen_t                  socklen;
    rp_str_t                  addr_text;

    unsigned                   set:1;
    unsigned                   default_server:1;
    unsigned                   bind:1;
    unsigned                   wildcard:1;
    unsigned                   ssl:1;
    unsigned                   http2:1;
#if (RP_HAVE_INET6)
    unsigned                   ipv6only:1;
#endif
    unsigned                   deferred_accept:1;
    unsigned                   reuseport:1;
    unsigned                   so_keepalive:2;
    unsigned                   proxy_protocol:1;

    int                        backlog;
    int                        rcvbuf;
    int                        sndbuf;
#if (RP_HAVE_SETFIB)
    int                        setfib;
#endif
#if (RP_HAVE_TCP_FASTOPEN)
    int                        fastopen;
#endif
#if (RP_HAVE_KEEPALIVE_TUNABLE)
    int                        tcp_keepidle;
    int                        tcp_keepintvl;
    int                        tcp_keepcnt;
#endif

#if (RP_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char                      *accept_filter;
#endif
} rp_http_listen_opt_t;


typedef enum {
    RP_HTTP_POST_READ_PHASE = 0,

    RP_HTTP_SERVER_REWRITE_PHASE,

    RP_HTTP_FIND_CONFIG_PHASE,
    RP_HTTP_REWRITE_PHASE,
    RP_HTTP_POST_REWRITE_PHASE,

    RP_HTTP_PREACCESS_PHASE,

    RP_HTTP_ACCESS_PHASE,
    RP_HTTP_POST_ACCESS_PHASE,

    RP_HTTP_PRECONTENT_PHASE,

    RP_HTTP_CONTENT_PHASE,

    RP_HTTP_LOG_PHASE
} rp_http_phases;

typedef struct rp_http_phase_handler_s  rp_http_phase_handler_t;

typedef rp_int_t (*rp_http_phase_handler_pt)(rp_http_request_t *r,
    rp_http_phase_handler_t *ph);

struct rp_http_phase_handler_s {
    rp_http_phase_handler_pt  checker;
    rp_http_handler_pt        handler;
    rp_uint_t                 next;
};


typedef struct {
    rp_http_phase_handler_t  *handlers;
    rp_uint_t                 server_rewrite_index;
    rp_uint_t                 location_rewrite_index;
} rp_http_phase_engine_t;


typedef struct {
    rp_array_t                handlers;
} rp_http_phase_t;


typedef struct {
    rp_array_t                servers;         /* rp_http_core_srv_conf_t */

    rp_http_phase_engine_t    phase_engine;

    rp_hash_t                 headers_in_hash;

    rp_hash_t                 variables_hash;

    rp_array_t                variables;         /* rp_http_variable_t */
    rp_array_t                prefix_variables;  /* rp_http_variable_t */
    rp_uint_t                 ncaptures;

    rp_uint_t                 server_names_hash_max_size;
    rp_uint_t                 server_names_hash_bucket_size;

    rp_uint_t                 variables_hash_max_size;
    rp_uint_t                 variables_hash_bucket_size;

    rp_hash_keys_arrays_t    *variables_keys;

    rp_array_t               *ports;

    rp_http_phase_t           phases[RP_HTTP_LOG_PHASE + 1];
} rp_http_core_main_conf_t;


typedef struct {
    /* array of the rp_http_server_name_t, "server_name" directive */
    rp_array_t                 server_names;

    /* server ctx */
    rp_http_conf_ctx_t        *ctx;

    u_char                     *file_name;
    rp_uint_t                  line;

    rp_str_t                   server_name;

    size_t                      connection_pool_size;
    size_t                      request_pool_size;
    size_t                      client_header_buffer_size;

    rp_bufs_t                  large_client_header_buffers;

    rp_msec_t                  client_header_timeout;

    rp_flag_t                  ignore_invalid_headers;
    rp_flag_t                  merge_slashes;
    rp_flag_t                  underscores_in_headers;

    unsigned                    listen:1;
#if (RP_PCRE)
    unsigned                    captures:1;
#endif

    rp_http_core_loc_conf_t  **named_locations;
} rp_http_core_srv_conf_t;


/* list of structures to find core_srv_conf quickly at run time */


typedef struct {
#if (RP_PCRE)
    rp_http_regex_t          *regex;
#endif
    rp_http_core_srv_conf_t  *server;   /* virtual name server conf */
    rp_str_t                  name;
} rp_http_server_name_t;


typedef struct {
    rp_hash_combined_t        names;

    rp_uint_t                 nregex;
    rp_http_server_name_t    *regex;
} rp_http_virtual_names_t;


struct rp_http_addr_conf_s {
    /* the default server configuration for this address:port */
    rp_http_core_srv_conf_t  *default_server;

    rp_http_virtual_names_t  *virtual_names;

    unsigned                   ssl:1;
    unsigned                   http2:1;
    unsigned                   proxy_protocol:1;
};


typedef struct {
    in_addr_t                  addr;
    rp_http_addr_conf_t       conf;
} rp_http_in_addr_t;


#if (RP_HAVE_INET6)

typedef struct {
    struct in6_addr            addr6;
    rp_http_addr_conf_t       conf;
} rp_http_in6_addr_t;

#endif


typedef struct {
    /* rp_http_in_addr_t or rp_http_in6_addr_t */
    void                      *addrs;
    rp_uint_t                 naddrs;
} rp_http_port_t;


typedef struct {
    rp_int_t                  family;
    in_port_t                  port;
    rp_array_t                addrs;     /* array of rp_http_conf_addr_t */
} rp_http_conf_port_t;


typedef struct {
    rp_http_listen_opt_t      opt;

    rp_hash_t                 hash;
    rp_hash_wildcard_t       *wc_head;
    rp_hash_wildcard_t       *wc_tail;

#if (RP_PCRE)
    rp_uint_t                 nregex;
    rp_http_server_name_t    *regex;
#endif

    /* the default server configuration for this address:port */
    rp_http_core_srv_conf_t  *default_server;
    rp_array_t                servers;  /* array of rp_http_core_srv_conf_t */
} rp_http_conf_addr_t;


typedef struct {
    rp_int_t                  status;
    rp_int_t                  overwrite;
    rp_http_complex_value_t   value;
    rp_str_t                  args;
} rp_http_err_page_t;


struct rp_http_core_loc_conf_s {
    rp_str_t     name;          /* location name */

#if (RP_PCRE)
    rp_http_regex_t  *regex;
#endif

    unsigned      noname:1;   /* "if () {}" block or limit_except */
    unsigned      lmt_excpt:1;
    unsigned      named:1;

    unsigned      exact_match:1;
    unsigned      noregex:1;

    unsigned      auto_redirect:1;
#if (RP_HTTP_GZIP)
    unsigned      gzip_disable_msie6:2;
    unsigned      gzip_disable_degradation:2;
#endif

    rp_http_location_tree_node_t   *static_locations;
#if (RP_PCRE)
    rp_http_core_loc_conf_t       **regex_locations;
#endif

    /* pointer to the modules' loc_conf */
    void        **loc_conf;

    uint32_t      limit_except;
    void        **limit_except_loc_conf;

    rp_http_handler_pt  handler;

    /* location name length for inclusive location with inherited alias */
    size_t        alias;
    rp_str_t     root;                    /* root, alias */
    rp_str_t     post_action;

    rp_array_t  *root_lengths;
    rp_array_t  *root_values;

    rp_array_t  *types;
    rp_hash_t    types_hash;
    rp_str_t     default_type;

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

    rp_http_complex_value_t  *limit_rate; /* limit_rate */
    rp_http_complex_value_t  *limit_rate_after; /* limit_rate_after */

    rp_msec_t    client_body_timeout;     /* client_body_timeout */
    rp_msec_t    send_timeout;            /* send_timeout */
    rp_msec_t    keepalive_timeout;       /* keepalive_timeout */
    rp_msec_t    lingering_time;          /* lingering_time */
    rp_msec_t    lingering_timeout;       /* lingering_timeout */
    rp_msec_t    resolver_timeout;        /* resolver_timeout */
    rp_msec_t    auth_delay;              /* auth_delay */

    rp_resolver_t  *resolver;             /* resolver */

    time_t        keepalive_header;        /* keepalive_timeout */

    rp_uint_t    keepalive_requests;      /* keepalive_requests */
    rp_uint_t    keepalive_disable;       /* keepalive_disable */
    rp_uint_t    satisfy;                 /* satisfy */
    rp_uint_t    lingering_close;         /* lingering_close */
    rp_uint_t    if_modified_since;       /* if_modified_since */
    rp_uint_t    max_ranges;              /* max_ranges */
    rp_uint_t    client_body_in_file_only; /* client_body_in_file_only */

    rp_flag_t    client_body_in_single_buffer;
                                           /* client_body_in_singe_buffer */
    rp_flag_t    internal;                /* internal */
    rp_flag_t    sendfile;                /* sendfile */
    rp_flag_t    aio;                     /* aio */
    rp_flag_t    aio_write;               /* aio_write */
    rp_flag_t    tcp_nopush;              /* tcp_nopush */
    rp_flag_t    tcp_nodelay;             /* tcp_nodelay */
    rp_flag_t    reset_timedout_connection; /* reset_timedout_connection */
    rp_flag_t    absolute_redirect;       /* absolute_redirect */
    rp_flag_t    server_name_in_redirect; /* server_name_in_redirect */
    rp_flag_t    port_in_redirect;        /* port_in_redirect */
    rp_flag_t    msie_padding;            /* msie_padding */
    rp_flag_t    msie_refresh;            /* msie_refresh */
    rp_flag_t    log_not_found;           /* log_not_found */
    rp_flag_t    log_subrequest;          /* log_subrequest */
    rp_flag_t    recursive_error_pages;   /* recursive_error_pages */
    rp_uint_t    server_tokens;           /* server_tokens */
    rp_flag_t    chunked_transfer_encoding; /* chunked_transfer_encoding */
    rp_flag_t    etag;                    /* etag */

#if (RP_HTTP_GZIP)
    rp_flag_t    gzip_vary;               /* gzip_vary */

    rp_uint_t    gzip_http_version;       /* gzip_http_version */
    rp_uint_t    gzip_proxied;            /* gzip_proxied */

#if (RP_PCRE)
    rp_array_t  *gzip_disable;            /* gzip_disable */
#endif
#endif

#if (RP_THREADS || RP_COMPAT)
    rp_thread_pool_t         *thread_pool;
    rp_http_complex_value_t  *thread_pool_value;
#endif

#if (RP_HAVE_OPENAT)
    rp_uint_t    disable_symlinks;        /* disable_symlinks */
    rp_http_complex_value_t  *disable_symlinks_from;
#endif

    rp_array_t  *error_pages;             /* error_page */

    rp_path_t   *client_body_temp_path;   /* client_body_temp_path */

    rp_open_file_cache_t  *open_file_cache;
    time_t        open_file_cache_valid;
    rp_uint_t    open_file_cache_min_uses;
    rp_flag_t    open_file_cache_errors;
    rp_flag_t    open_file_cache_events;

    rp_log_t    *error_log;

    rp_uint_t    types_hash_max_size;
    rp_uint_t    types_hash_bucket_size;

    rp_queue_t  *locations;

#if 0
    rp_http_core_loc_conf_t  *prev_location;
#endif
};


typedef struct {
    rp_queue_t                      queue;
    rp_http_core_loc_conf_t        *exact;
    rp_http_core_loc_conf_t        *inclusive;
    rp_str_t                       *name;
    u_char                          *file_name;
    rp_uint_t                       line;
    rp_queue_t                      list;
} rp_http_location_queue_t;


struct rp_http_location_tree_node_s {
    rp_http_location_tree_node_t   *left;
    rp_http_location_tree_node_t   *right;
    rp_http_location_tree_node_t   *tree;

    rp_http_core_loc_conf_t        *exact;
    rp_http_core_loc_conf_t        *inclusive;

    u_char                           auto_redirect;
    u_char                           len;
    u_char                           name[1];
};


void rp_http_core_run_phases(rp_http_request_t *r);
rp_int_t rp_http_core_generic_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph);
rp_int_t rp_http_core_rewrite_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph);
rp_int_t rp_http_core_find_config_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph);
rp_int_t rp_http_core_post_rewrite_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph);
rp_int_t rp_http_core_access_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph);
rp_int_t rp_http_core_post_access_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph);
rp_int_t rp_http_core_content_phase(rp_http_request_t *r,
    rp_http_phase_handler_t *ph);


void *rp_http_test_content_type(rp_http_request_t *r, rp_hash_t *types_hash);
rp_int_t rp_http_set_content_type(rp_http_request_t *r);
void rp_http_set_exten(rp_http_request_t *r);
rp_int_t rp_http_set_etag(rp_http_request_t *r);
void rp_http_weak_etag(rp_http_request_t *r);
rp_int_t rp_http_send_response(rp_http_request_t *r, rp_uint_t status,
    rp_str_t *ct, rp_http_complex_value_t *cv);
u_char *rp_http_map_uri_to_path(rp_http_request_t *r, rp_str_t *name,
    size_t *root_length, size_t reserved);
rp_int_t rp_http_auth_basic_user(rp_http_request_t *r);
#if (RP_HTTP_GZIP)
rp_int_t rp_http_gzip_ok(rp_http_request_t *r);
#endif


rp_int_t rp_http_subrequest(rp_http_request_t *r,
    rp_str_t *uri, rp_str_t *args, rp_http_request_t **sr,
    rp_http_post_subrequest_t *psr, rp_uint_t flags);
rp_int_t rp_http_internal_redirect(rp_http_request_t *r,
    rp_str_t *uri, rp_str_t *args);
rp_int_t rp_http_named_location(rp_http_request_t *r, rp_str_t *name);


rp_http_cleanup_t *rp_http_cleanup_add(rp_http_request_t *r, size_t size);


typedef rp_int_t (*rp_http_output_header_filter_pt)(rp_http_request_t *r);
typedef rp_int_t (*rp_http_output_body_filter_pt)
    (rp_http_request_t *r, rp_chain_t *chain);
typedef rp_int_t (*rp_http_request_body_filter_pt)
    (rp_http_request_t *r, rp_chain_t *chain);


rp_int_t rp_http_output_filter(rp_http_request_t *r, rp_chain_t *chain);
rp_int_t rp_http_write_filter(rp_http_request_t *r, rp_chain_t *chain);
rp_int_t rp_http_request_body_save_filter(rp_http_request_t *r,
    rp_chain_t *chain);


rp_int_t rp_http_set_disable_symlinks(rp_http_request_t *r,
    rp_http_core_loc_conf_t *clcf, rp_str_t *path, rp_open_file_info_t *of);

rp_int_t rp_http_get_forwarded_addr(rp_http_request_t *r, rp_addr_t *addr,
    rp_array_t *headers, rp_str_t *value, rp_array_t *proxies,
    int recursive);


extern rp_module_t  rp_http_core_module;

extern rp_uint_t rp_http_max_module;

extern rp_str_t  rp_http_core_get_method;


#define rp_http_clear_content_length(r)                                      \
                                                                              \
    r->headers_out.content_length_n = -1;                                     \
    if (r->headers_out.content_length) {                                      \
        r->headers_out.content_length->hash = 0;                              \
        r->headers_out.content_length = NULL;                                 \
    }

#define rp_http_clear_accept_ranges(r)                                       \
                                                                              \
    r->allow_ranges = 0;                                                      \
    if (r->headers_out.accept_ranges) {                                       \
        r->headers_out.accept_ranges->hash = 0;                               \
        r->headers_out.accept_ranges = NULL;                                  \
    }

#define rp_http_clear_last_modified(r)                                       \
                                                                              \
    r->headers_out.last_modified_time = -1;                                   \
    if (r->headers_out.last_modified) {                                       \
        r->headers_out.last_modified->hash = 0;                               \
        r->headers_out.last_modified = NULL;                                  \
    }

#define rp_http_clear_location(r)                                            \
                                                                              \
    if (r->headers_out.location) {                                            \
        r->headers_out.location->hash = 0;                                    \
        r->headers_out.location = NULL;                                       \
    }

#define rp_http_clear_etag(r)                                                \
                                                                              \
    if (r->headers_out.etag) {                                                \
        r->headers_out.etag->hash = 0;                                        \
        r->headers_out.etag = NULL;                                           \
    }


#endif /* _RP_HTTP_CORE_H_INCLUDED_ */
