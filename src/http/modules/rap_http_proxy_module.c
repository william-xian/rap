
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_array_t                    caches;  /* rap_http_file_cache_t * */
} rap_http_proxy_main_conf_t;


typedef struct rap_http_proxy_rewrite_s  rap_http_proxy_rewrite_t;

typedef rap_int_t (*rap_http_proxy_rewrite_pt)(rap_http_request_t *r,
    rap_table_elt_t *h, size_t prefix, size_t len,
    rap_http_proxy_rewrite_t *pr);

struct rap_http_proxy_rewrite_s {
    rap_http_proxy_rewrite_pt      handler;

    union {
        rap_http_complex_value_t   complex;
#if (RAP_PCRE)
        rap_http_regex_t          *regex;
#endif
    } pattern;

    rap_http_complex_value_t       replacement;
};


typedef struct {
    rap_str_t                      key_start;
    rap_str_t                      schema;
    rap_str_t                      host_header;
    rap_str_t                      port;
    rap_str_t                      uri;
} rap_http_proxy_vars_t;


typedef struct {
    rap_array_t                   *flushes;
    rap_array_t                   *lengths;
    rap_array_t                   *values;
    rap_hash_t                     hash;
} rap_http_proxy_headers_t;


typedef struct {
    rap_http_upstream_conf_t       upstream;

    rap_array_t                   *body_flushes;
    rap_array_t                   *body_lengths;
    rap_array_t                   *body_values;
    rap_str_t                      body_source;

    rap_http_proxy_headers_t       headers;
#if (RAP_HTTP_CACHE)
    rap_http_proxy_headers_t       headers_cache;
#endif
    rap_array_t                   *headers_source;

    rap_array_t                   *proxy_lengths;
    rap_array_t                   *proxy_values;

    rap_array_t                   *redirects;
    rap_array_t                   *cookie_domains;
    rap_array_t                   *cookie_paths;

    rap_http_complex_value_t      *method;
    rap_str_t                      location;
    rap_str_t                      url;

#if (RAP_HTTP_CACHE)
    rap_http_complex_value_t       cache_key;
#endif

    rap_http_proxy_vars_t          vars;

    rap_flag_t                     redirect;

    rap_uint_t                     http_version;

    rap_uint_t                     headers_hash_max_size;
    rap_uint_t                     headers_hash_bucket_size;

#if (RAP_HTTP_SSL)
    rap_uint_t                     ssl;
    rap_uint_t                     ssl_protocols;
    rap_str_t                      ssl_ciphers;
    rap_uint_t                     ssl_verify_depth;
    rap_str_t                      ssl_trusted_certificate;
    rap_str_t                      ssl_crl;
    rap_str_t                      ssl_certificate;
    rap_str_t                      ssl_certificate_key;
    rap_array_t                   *ssl_passwords;
#endif
} rap_http_proxy_loc_conf_t;


typedef struct {
    rap_http_status_t              status;
    rap_http_chunked_t             chunked;
    rap_http_proxy_vars_t          vars;
    off_t                          internal_body_length;

    rap_chain_t                   *free;
    rap_chain_t                   *busy;

    unsigned                       head:1;
    unsigned                       internal_chunked:1;
    unsigned                       header_sent:1;
} rap_http_proxy_ctx_t;


static rap_int_t rap_http_proxy_eval(rap_http_request_t *r,
    rap_http_proxy_ctx_t *ctx, rap_http_proxy_loc_conf_t *plcf);
#if (RAP_HTTP_CACHE)
static rap_int_t rap_http_proxy_create_key(rap_http_request_t *r);
#endif
static rap_int_t rap_http_proxy_create_request(rap_http_request_t *r);
static rap_int_t rap_http_proxy_reinit_request(rap_http_request_t *r);
static rap_int_t rap_http_proxy_body_output_filter(void *data, rap_chain_t *in);
static rap_int_t rap_http_proxy_process_status_line(rap_http_request_t *r);
static rap_int_t rap_http_proxy_process_header(rap_http_request_t *r);
static rap_int_t rap_http_proxy_input_filter_init(void *data);
static rap_int_t rap_http_proxy_copy_filter(rap_event_pipe_t *p,
    rap_buf_t *buf);
static rap_int_t rap_http_proxy_chunked_filter(rap_event_pipe_t *p,
    rap_buf_t *buf);
static rap_int_t rap_http_proxy_non_buffered_copy_filter(void *data,
    ssize_t bytes);
static rap_int_t rap_http_proxy_non_buffered_chunked_filter(void *data,
    ssize_t bytes);
static void rap_http_proxy_abort_request(rap_http_request_t *r);
static void rap_http_proxy_finalize_request(rap_http_request_t *r,
    rap_int_t rc);

static rap_int_t rap_http_proxy_host_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_proxy_port_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t
    rap_http_proxy_add_x_forwarded_for_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t
    rap_http_proxy_internal_body_length_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_proxy_internal_chunked_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_proxy_rewrite_redirect(rap_http_request_t *r,
    rap_table_elt_t *h, size_t prefix);
static rap_int_t rap_http_proxy_rewrite_cookie(rap_http_request_t *r,
    rap_table_elt_t *h);
static rap_int_t rap_http_proxy_rewrite_cookie_value(rap_http_request_t *r,
    rap_table_elt_t *h, u_char *value, rap_array_t *rewrites);
static rap_int_t rap_http_proxy_rewrite(rap_http_request_t *r,
    rap_table_elt_t *h, size_t prefix, size_t len, rap_str_t *replacement);

static rap_int_t rap_http_proxy_add_variables(rap_conf_t *cf);
static void *rap_http_proxy_create_main_conf(rap_conf_t *cf);
static void *rap_http_proxy_create_loc_conf(rap_conf_t *cf);
static char *rap_http_proxy_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_proxy_init_headers(rap_conf_t *cf,
    rap_http_proxy_loc_conf_t *conf, rap_http_proxy_headers_t *headers,
    rap_keyval_t *default_headers);

static char *rap_http_proxy_pass(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_proxy_redirect(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_proxy_cookie_domain(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_proxy_cookie_path(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_proxy_store(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
#if (RAP_HTTP_CACHE)
static char *rap_http_proxy_cache(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_proxy_cache_key(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
#endif
#if (RAP_HTTP_SSL)
static char *rap_http_proxy_ssl_password_file(rap_conf_t *cf,
    rap_command_t *cmd, void *conf);
#endif

static char *rap_http_proxy_lowat_check(rap_conf_t *cf, void *post, void *data);

static rap_int_t rap_http_proxy_rewrite_regex(rap_conf_t *cf,
    rap_http_proxy_rewrite_t *pr, rap_str_t *regex, rap_uint_t caseless);

#if (RAP_HTTP_SSL)
static rap_int_t rap_http_proxy_set_ssl(rap_conf_t *cf,
    rap_http_proxy_loc_conf_t *plcf);
#endif
static void rap_http_proxy_set_vars(rap_url_t *u, rap_http_proxy_vars_t *v);


static rap_conf_post_t  rap_http_proxy_lowat_post =
    { rap_http_proxy_lowat_check };


static rap_conf_bitmask_t  rap_http_proxy_next_upstream_masks[] = {
    { rap_string("error"), RAP_HTTP_UPSTREAM_FT_ERROR },
    { rap_string("timeout"), RAP_HTTP_UPSTREAM_FT_TIMEOUT },
    { rap_string("invalid_header"), RAP_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { rap_string("non_idempotent"), RAP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { rap_string("http_500"), RAP_HTTP_UPSTREAM_FT_HTTP_500 },
    { rap_string("http_502"), RAP_HTTP_UPSTREAM_FT_HTTP_502 },
    { rap_string("http_503"), RAP_HTTP_UPSTREAM_FT_HTTP_503 },
    { rap_string("http_504"), RAP_HTTP_UPSTREAM_FT_HTTP_504 },
    { rap_string("http_403"), RAP_HTTP_UPSTREAM_FT_HTTP_403 },
    { rap_string("http_404"), RAP_HTTP_UPSTREAM_FT_HTTP_404 },
    { rap_string("http_429"), RAP_HTTP_UPSTREAM_FT_HTTP_429 },
    { rap_string("updating"), RAP_HTTP_UPSTREAM_FT_UPDATING },
    { rap_string("off"), RAP_HTTP_UPSTREAM_FT_OFF },
    { rap_null_string, 0 }
};


#if (RAP_HTTP_SSL)

static rap_conf_bitmask_t  rap_http_proxy_ssl_protocols[] = {
    { rap_string("SSLv2"), RAP_SSL_SSLv2 },
    { rap_string("SSLv3"), RAP_SSL_SSLv3 },
    { rap_string("TLSv1"), RAP_SSL_TLSv1 },
    { rap_string("TLSv1.1"), RAP_SSL_TLSv1_1 },
    { rap_string("TLSv1.2"), RAP_SSL_TLSv1_2 },
    { rap_string("TLSv1.3"), RAP_SSL_TLSv1_3 },
    { rap_null_string, 0 }
};

#endif


static rap_conf_enum_t  rap_http_proxy_http_version[] = {
    { rap_string("1.0"), RAP_HTTP_VERSION_10 },
    { rap_string("1.1"), RAP_HTTP_VERSION_11 },
    { rap_null_string, 0 }
};


rap_module_t  rap_http_proxy_module;


static rap_command_t  rap_http_proxy_commands[] = {

    { rap_string("proxy_pass"),
      RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF|RAP_HTTP_LMT_CONF|RAP_CONF_TAKE1,
      rap_http_proxy_pass,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("proxy_redirect"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_proxy_redirect,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("proxy_cookie_domain"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_proxy_cookie_domain,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("proxy_cookie_path"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_proxy_cookie_path,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("proxy_store"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_proxy_store,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("proxy_store_access"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE123,
      rap_conf_set_access_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.store_access),
      NULL },

    { rap_string("proxy_buffering"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.buffering),
      NULL },

    { rap_string("proxy_request_buffering"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.request_buffering),
      NULL },

    { rap_string("proxy_ignore_client_abort"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { rap_string("proxy_bind"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_upstream_bind_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.local),
      NULL },

    { rap_string("proxy_socket_keepalive"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { rap_string("proxy_connect_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.connect_timeout),
      NULL },

    { rap_string("proxy_send_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.send_timeout),
      NULL },

    { rap_string("proxy_send_lowat"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.send_lowat),
      &rap_http_proxy_lowat_post },

    { rap_string("proxy_intercept_errors"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.intercept_errors),
      NULL },

    { rap_string("proxy_set_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_conf_set_keyval_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, headers_source),
      NULL },

    { rap_string("proxy_headers_hash_max_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, headers_hash_max_size),
      NULL },

    { rap_string("proxy_headers_hash_bucket_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, headers_hash_bucket_size),
      NULL },

    { rap_string("proxy_set_body"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, body_source),
      NULL },

    { rap_string("proxy_method"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_set_complex_value_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, method),
      NULL },

    { rap_string("proxy_pass_request_headers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { rap_string("proxy_pass_request_body"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.pass_request_body),
      NULL },

    { rap_string("proxy_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.buffer_size),
      NULL },

    { rap_string("proxy_read_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.read_timeout),
      NULL },

    { rap_string("proxy_buffers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_conf_set_bufs_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.bufs),
      NULL },

    { rap_string("proxy_busy_buffers_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { rap_string("proxy_force_ranges"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.force_ranges),
      NULL },

    { rap_string("proxy_limit_rate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.limit_rate),
      NULL },

#if (RAP_HTTP_CACHE)

    { rap_string("proxy_cache"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_proxy_cache,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("proxy_cache_key"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_proxy_cache_key,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("proxy_cache_path"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_2MORE,
      rap_http_file_cache_set_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_proxy_main_conf_t, caches),
      &rap_http_proxy_module },

    { rap_string("proxy_cache_bypass"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_set_predicate_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_bypass),
      NULL },

    { rap_string("proxy_no_cache"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_set_predicate_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.no_cache),
      NULL },

    { rap_string("proxy_cache_valid"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_file_cache_valid_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_valid),
      NULL },

    { rap_string("proxy_cache_min_uses"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { rap_string("proxy_cache_max_range_offset"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_off_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { rap_string("proxy_cache_use_stale"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_use_stale),
      &rap_http_proxy_next_upstream_masks },

    { rap_string("proxy_cache_methods"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_methods),
      &rap_http_upstream_cache_method_mask },

    { rap_string("proxy_cache_lock"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_lock),
      NULL },

    { rap_string("proxy_cache_lock_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { rap_string("proxy_cache_lock_age"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { rap_string("proxy_cache_revalidate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { rap_string("proxy_cache_convert_head"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_convert_head),
      NULL },

    { rap_string("proxy_cache_background_update"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { rap_string("proxy_temp_path"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1234,
      rap_conf_set_path_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.temp_path),
      NULL },

    { rap_string("proxy_max_temp_file_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { rap_string("proxy_temp_file_write_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { rap_string("proxy_next_upstream"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.next_upstream),
      &rap_http_proxy_next_upstream_masks },

    { rap_string("proxy_next_upstream_tries"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { rap_string("proxy_next_upstream_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { rap_string("proxy_pass_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.pass_headers),
      NULL },

    { rap_string("proxy_hide_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.hide_headers),
      NULL },

    { rap_string("proxy_ignore_headers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.ignore_headers),
      &rap_http_upstream_ignore_headers_masks },

    { rap_string("proxy_http_version"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, http_version),
      &rap_http_proxy_http_version },

#if (RAP_HTTP_SSL)

    { rap_string("proxy_ssl_session_reuse"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { rap_string("proxy_ssl_protocols"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, ssl_protocols),
      &rap_http_proxy_ssl_protocols },

    { rap_string("proxy_ssl_ciphers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, ssl_ciphers),
      NULL },

    { rap_string("proxy_ssl_name"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_set_complex_value_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.ssl_name),
      NULL },

    { rap_string("proxy_ssl_server_name"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { rap_string("proxy_ssl_verify"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, upstream.ssl_verify),
      NULL },

    { rap_string("proxy_ssl_verify_depth"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, ssl_verify_depth),
      NULL },

    { rap_string("proxy_ssl_trusted_certificate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { rap_string("proxy_ssl_crl"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, ssl_crl),
      NULL },

    { rap_string("proxy_ssl_certificate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, ssl_certificate),
      NULL },

    { rap_string("proxy_ssl_certificate_key"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_proxy_loc_conf_t, ssl_certificate_key),
      NULL },

    { rap_string("proxy_ssl_password_file"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_proxy_ssl_password_file,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

      rap_null_command
};


static rap_http_module_t  rap_http_proxy_module_ctx = {
    rap_http_proxy_add_variables,          /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_http_proxy_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_proxy_create_loc_conf,        /* create location configuration */
    rap_http_proxy_merge_loc_conf          /* merge location configuration */
};


rap_module_t  rap_http_proxy_module = {
    RAP_MODULE_V1,
    &rap_http_proxy_module_ctx,            /* module context */
    rap_http_proxy_commands,               /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static char  rap_http_proxy_version[] = " HTTP/1.0" CRLF;
static char  rap_http_proxy_version_11[] = " HTTP/1.1" CRLF;


static rap_keyval_t  rap_http_proxy_headers[] = {
    { rap_string("Host"), rap_string("$proxy_host") },
    { rap_string("Connection"), rap_string("close") },
    { rap_string("Content-Length"), rap_string("$proxy_internal_body_length") },
    { rap_string("Transfer-Encoding"), rap_string("$proxy_internal_chunked") },
    { rap_string("TE"), rap_string("") },
    { rap_string("Keep-Alive"), rap_string("") },
    { rap_string("Expect"), rap_string("") },
    { rap_string("Upgrade"), rap_string("") },
    { rap_null_string, rap_null_string }
};


static rap_str_t  rap_http_proxy_hide_headers[] = {
    rap_string("Date"),
    rap_string("Server"),
    rap_string("X-Pad"),
    rap_string("X-Accel-Expires"),
    rap_string("X-Accel-Redirect"),
    rap_string("X-Accel-Limit-Rate"),
    rap_string("X-Accel-Buffering"),
    rap_string("X-Accel-Charset"),
    rap_null_string
};


#if (RAP_HTTP_CACHE)

static rap_keyval_t  rap_http_proxy_cache_headers[] = {
    { rap_string("Host"), rap_string("$proxy_host") },
    { rap_string("Connection"), rap_string("close") },
    { rap_string("Content-Length"), rap_string("$proxy_internal_body_length") },
    { rap_string("Transfer-Encoding"), rap_string("$proxy_internal_chunked") },
    { rap_string("TE"), rap_string("") },
    { rap_string("Keep-Alive"), rap_string("") },
    { rap_string("Expect"), rap_string("") },
    { rap_string("Upgrade"), rap_string("") },
    { rap_string("If-Modified-Since"),
      rap_string("$upstream_cache_last_modified") },
    { rap_string("If-Unmodified-Since"), rap_string("") },
    { rap_string("If-None-Match"), rap_string("$upstream_cache_etag") },
    { rap_string("If-Match"), rap_string("") },
    { rap_string("Range"), rap_string("") },
    { rap_string("If-Range"), rap_string("") },
    { rap_null_string, rap_null_string }
};

#endif


static rap_http_variable_t  rap_http_proxy_vars[] = {

    { rap_string("proxy_host"), NULL, rap_http_proxy_host_variable, 0,
      RAP_HTTP_VAR_CHANGEABLE|RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_NOHASH, 0 },

    { rap_string("proxy_port"), NULL, rap_http_proxy_port_variable, 0,
      RAP_HTTP_VAR_CHANGEABLE|RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_NOHASH, 0 },

    { rap_string("proxy_add_x_forwarded_for"), NULL,
      rap_http_proxy_add_x_forwarded_for_variable, 0, RAP_HTTP_VAR_NOHASH, 0 },

#if 0
    { rap_string("proxy_add_via"), NULL, NULL, 0, RAP_HTTP_VAR_NOHASH, 0 },
#endif

    { rap_string("proxy_internal_body_length"), NULL,
      rap_http_proxy_internal_body_length_variable, 0,
      RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_NOHASH, 0 },

    { rap_string("proxy_internal_chunked"), NULL,
      rap_http_proxy_internal_chunked_variable, 0,
      RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_NOHASH, 0 },

      rap_http_null_variable
};


static rap_path_init_t  rap_http_proxy_temp_path = {
    rap_string(RAP_HTTP_PROXY_TEMP_PATH), { 1, 2, 0 }
};


static rap_int_t
rap_http_proxy_handler(rap_http_request_t *r)
{
    rap_int_t                    rc;
    rap_http_upstream_t         *u;
    rap_http_proxy_ctx_t        *ctx;
    rap_http_proxy_loc_conf_t   *plcf;
#if (RAP_HTTP_CACHE)
    rap_http_proxy_main_conf_t  *pmcf;
#endif

    if (rap_http_upstream_create(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_proxy_ctx_t));
    if (ctx == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rap_http_set_ctx(r, ctx, rap_http_proxy_module);

    plcf = rap_http_get_module_loc_conf(r, rap_http_proxy_module);

    u = r->upstream;

    if (plcf->proxy_lengths == NULL) {
        ctx->vars = plcf->vars;
        u->schema = plcf->vars.schema;
#if (RAP_HTTP_SSL)
        u->ssl = (plcf->upstream.ssl != NULL);
#endif

    } else {
        if (rap_http_proxy_eval(r, ctx, plcf) != RAP_OK) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (rap_buf_tag_t) &rap_http_proxy_module;

    u->conf = &plcf->upstream;

#if (RAP_HTTP_CACHE)
    pmcf = rap_http_get_module_main_conf(r, rap_http_proxy_module);

    u->caches = &pmcf->caches;
    u->create_key = rap_http_proxy_create_key;
#endif

    u->create_request = rap_http_proxy_create_request;
    u->reinit_request = rap_http_proxy_reinit_request;
    u->process_header = rap_http_proxy_process_status_line;
    u->abort_request = rap_http_proxy_abort_request;
    u->finalize_request = rap_http_proxy_finalize_request;
    r->state = 0;

    if (plcf->redirects) {
        u->rewrite_redirect = rap_http_proxy_rewrite_redirect;
    }

    if (plcf->cookie_domains || plcf->cookie_paths) {
        u->rewrite_cookie = rap_http_proxy_rewrite_cookie;
    }

    u->buffering = plcf->upstream.buffering;

    u->pipe = rap_pcalloc(r->pool, sizeof(rap_event_pipe_t));
    if (u->pipe == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = rap_http_proxy_copy_filter;
    u->pipe->input_ctx = r;

    u->input_filter_init = rap_http_proxy_input_filter_init;
    u->input_filter = rap_http_proxy_non_buffered_copy_filter;
    u->input_filter_ctx = r;

    u->accel = 1;

    if (!plcf->upstream.request_buffering
        && plcf->body_values == NULL && plcf->upstream.pass_request_body
        && (!r->headers_in.chunked
            || plcf->http_version == RAP_HTTP_VERSION_11))
    {
        r->request_body_no_buffering = 1;
    }

    rc = rap_http_read_client_request_body(r, rap_http_upstream_init);

    if (rc >= RAP_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return RAP_DONE;
}


static rap_int_t
rap_http_proxy_eval(rap_http_request_t *r, rap_http_proxy_ctx_t *ctx,
    rap_http_proxy_loc_conf_t *plcf)
{
    u_char               *p;
    size_t                add;
    u_short               port;
    rap_str_t             proxy;
    rap_url_t             url;
    rap_http_upstream_t  *u;

    if (rap_http_script_run(r, &proxy, plcf->proxy_lengths->elts, 0,
                            plcf->proxy_values->elts)
        == NULL)
    {
        return RAP_ERROR;
    }

    if (proxy.len > 7
        && rap_strncasecmp(proxy.data, (u_char *) "http://", 7) == 0)
    {
        add = 7;
        port = 80;

#if (RAP_HTTP_SSL)

    } else if (proxy.len > 8
               && rap_strncasecmp(proxy.data, (u_char *) "https://", 8) == 0)
    {
        add = 8;
        port = 443;
        r->upstream->ssl = 1;

#endif

    } else {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "invalid URL prefix in \"%V\"", &proxy);
        return RAP_ERROR;
    }

    u = r->upstream;

    u->schema.len = add;
    u->schema.data = proxy.data;

    rap_memzero(&url, sizeof(rap_url_t));

    url.url.len = proxy.len - add;
    url.url.data = proxy.data + add;
    url.default_port = port;
    url.uri_part = 1;
    url.no_resolve = 1;

    if (rap_parse_url(r->pool, &url) != RAP_OK) {
        if (url.err) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return RAP_ERROR;
    }

    if (url.uri.len) {
        if (url.uri.data[0] == '?') {
            p = rap_pnalloc(r->pool, url.uri.len + 1);
            if (p == NULL) {
                return RAP_ERROR;
            }

            *p++ = '/';
            rap_memcpy(p, url.uri.data, url.uri.len);

            url.uri.len++;
            url.uri.data = p - 1;
        }
    }

    ctx->vars.key_start = u->schema;

    rap_http_proxy_set_vars(&url, &ctx->vars);

    u->resolved = rap_pcalloc(r->pool, sizeof(rap_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return RAP_ERROR;
    }

    if (url.addrs) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->name = url.addrs[0].name;
        u->resolved->naddrs = 1;
    }

    u->resolved->host = url.host;
    u->resolved->port = (in_port_t) (url.no_port ? port : url.port);
    u->resolved->no_port = url.no_port;

    return RAP_OK;
}


#if (RAP_HTTP_CACHE)

static rap_int_t
rap_http_proxy_create_key(rap_http_request_t *r)
{
    size_t                      len, loc_len;
    u_char                     *p;
    uintptr_t                   escape;
    rap_str_t                  *key;
    rap_http_upstream_t        *u;
    rap_http_proxy_ctx_t       *ctx;
    rap_http_proxy_loc_conf_t  *plcf;

    u = r->upstream;

    plcf = rap_http_get_module_loc_conf(r, rap_http_proxy_module);

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    key = rap_array_push(&r->cache->keys);
    if (key == NULL) {
        return RAP_ERROR;
    }

    if (plcf->cache_key.value.data) {

        if (rap_http_complex_value(r, &plcf->cache_key, key) != RAP_OK) {
            return RAP_ERROR;
        }

        return RAP_OK;
    }

    *key = ctx->vars.key_start;

    key = rap_array_push(&r->cache->keys);
    if (key == NULL) {
        return RAP_ERROR;
    }

    if (plcf->proxy_lengths && ctx->vars.uri.len) {

        *key = ctx->vars.uri;
        u->uri = ctx->vars.uri;

        return RAP_OK;

    } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
        *key = r->unparsed_uri;
        u->uri = r->unparsed_uri;

        return RAP_OK;
    }

    loc_len = (r->valid_location && ctx->vars.uri.len) ? plcf->location.len : 0;

    if (r->quoted_uri || r->space_in_uri || r->internal) {
        escape = 2 * rap_escape_uri(NULL, r->uri.data + loc_len,
                                    r->uri.len - loc_len, RAP_ESCAPE_URI);
    } else {
        escape = 0;
    }

    len = ctx->vars.uri.len + r->uri.len - loc_len + escape
          + sizeof("?") - 1 + r->args.len;

    p = rap_pnalloc(r->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    key->data = p;

    if (r->valid_location) {
        p = rap_copy(p, ctx->vars.uri.data, ctx->vars.uri.len);
    }

    if (escape) {
        rap_escape_uri(p, r->uri.data + loc_len,
                       r->uri.len - loc_len, RAP_ESCAPE_URI);
        p += r->uri.len - loc_len + escape;

    } else {
        p = rap_copy(p, r->uri.data + loc_len, r->uri.len - loc_len);
    }

    if (r->args.len > 0) {
        *p++ = '?';
        p = rap_copy(p, r->args.data, r->args.len);
    }

    key->len = p - key->data;
    u->uri = *key;

    return RAP_OK;
}

#endif


static rap_int_t
rap_http_proxy_create_request(rap_http_request_t *r)
{
    size_t                        len, uri_len, loc_len, body_len,
                                  key_len, val_len;
    uintptr_t                     escape;
    rap_buf_t                    *b;
    rap_str_t                     method;
    rap_uint_t                    i, unparsed_uri;
    rap_chain_t                  *cl, *body;
    rap_list_part_t              *part;
    rap_table_elt_t              *header;
    rap_http_upstream_t          *u;
    rap_http_proxy_ctx_t         *ctx;
    rap_http_script_code_pt       code;
    rap_http_proxy_headers_t     *headers;
    rap_http_script_engine_t      e, le;
    rap_http_proxy_loc_conf_t    *plcf;
    rap_http_script_len_code_pt   lcode;

    u = r->upstream;

    plcf = rap_http_get_module_loc_conf(r, rap_http_proxy_module);

#if (RAP_HTTP_CACHE)
    headers = u->cacheable ? &plcf->headers_cache : &plcf->headers;
#else
    headers = &plcf->headers;
#endif

    if (u->method.len) {
        /* HEAD was changed to GET to cache response */
        method = u->method;

    } else if (plcf->method) {
        if (rap_http_complex_value(r, plcf->method, &method) != RAP_OK) {
            return RAP_ERROR;
        }

    } else {
        method = r->method_name;
    }

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (method.len == 4
        && rap_strncasecmp(method.data, (u_char *) "HEAD", 4) == 0)
    {
        ctx->head = 1;
    }

    len = method.len + 1 + sizeof(rap_http_proxy_version) - 1
          + sizeof(CRLF) - 1;

    escape = 0;
    loc_len = 0;
    unparsed_uri = 0;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        uri_len = ctx->vars.uri.len;

    } else if (ctx->vars.uri.len == 0 && r->valid_unparsed_uri) {
        unparsed_uri = 1;
        uri_len = r->unparsed_uri.len;

    } else {
        loc_len = (r->valid_location && ctx->vars.uri.len) ?
                      plcf->location.len : 0;

        if (r->quoted_uri || r->space_in_uri || r->internal) {
            escape = 2 * rap_escape_uri(NULL, r->uri.data + loc_len,
                                        r->uri.len - loc_len, RAP_ESCAPE_URI);
        }

        uri_len = ctx->vars.uri.len + r->uri.len - loc_len + escape
                  + sizeof("?") - 1 + r->args.len;
    }

    if (uri_len == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "zero length URI to proxy");
        return RAP_ERROR;
    }

    len += uri_len;

    rap_memzero(&le, sizeof(rap_http_script_engine_t));

    rap_http_script_flush_no_cacheable_variables(r, plcf->body_flushes);
    rap_http_script_flush_no_cacheable_variables(r, headers->flushes);

    if (plcf->body_lengths) {
        le.ip = plcf->body_lengths->elts;
        le.request = r;
        le.flushed = 1;
        body_len = 0;

        while (*(uintptr_t *) le.ip) {
            lcode = *(rap_http_script_len_code_pt *) le.ip;
            body_len += lcode(&le);
        }

        ctx->internal_body_length = body_len;
        len += body_len;

    } else if (r->headers_in.chunked && r->reading_body) {
        ctx->internal_body_length = -1;
        ctx->internal_chunked = 1;

    } else {
        ctx->internal_body_length = r->headers_in.content_length_n;
    }

    le.ip = headers->lengths->elts;
    le.request = r;
    le.flushed = 1;

    while (*(uintptr_t *) le.ip) {

        lcode = *(rap_http_script_len_code_pt *) le.ip;
        key_len = lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(rap_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            continue;
        }

        len += key_len + sizeof(": ") - 1 + val_len + sizeof(CRLF) - 1;
    }


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (rap_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            len += header[i].key.len + sizeof(": ") - 1
                + header[i].value.len + sizeof(CRLF) - 1;
        }
    }


    b = rap_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return RAP_ERROR;
    }

    cl = rap_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    cl->buf = b;


    /* the request line */

    b->last = rap_copy(b->last, method.data, method.len);
    *b->last++ = ' ';

    u->uri.data = b->last;

    if (plcf->proxy_lengths && ctx->vars.uri.len) {
        b->last = rap_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);

    } else if (unparsed_uri) {
        b->last = rap_copy(b->last, r->unparsed_uri.data, r->unparsed_uri.len);

    } else {
        if (r->valid_location) {
            b->last = rap_copy(b->last, ctx->vars.uri.data, ctx->vars.uri.len);
        }

        if (escape) {
            rap_escape_uri(b->last, r->uri.data + loc_len,
                           r->uri.len - loc_len, RAP_ESCAPE_URI);
            b->last += r->uri.len - loc_len + escape;

        } else {
            b->last = rap_copy(b->last, r->uri.data + loc_len,
                               r->uri.len - loc_len);
        }

        if (r->args.len > 0) {
            *b->last++ = '?';
            b->last = rap_copy(b->last, r->args.data, r->args.len);
        }
    }

    u->uri.len = b->last - u->uri.data;

    if (plcf->http_version == RAP_HTTP_VERSION_11) {
        b->last = rap_cpymem(b->last, rap_http_proxy_version_11,
                             sizeof(rap_http_proxy_version_11) - 1);

    } else {
        b->last = rap_cpymem(b->last, rap_http_proxy_version,
                             sizeof(rap_http_proxy_version) - 1);
    }

    rap_memzero(&e, sizeof(rap_http_script_engine_t));

    e.ip = headers->values->elts;
    e.pos = b->last;
    e.request = r;
    e.flushed = 1;

    le.ip = headers->lengths->elts;

    while (*(uintptr_t *) le.ip) {

        lcode = *(rap_http_script_len_code_pt *) le.ip;
        (void) lcode(&le);

        for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
            lcode = *(rap_http_script_len_code_pt *) le.ip;
        }
        le.ip += sizeof(uintptr_t);

        if (val_len == 0) {
            e.skip = 1;

            while (*(uintptr_t *) e.ip) {
                code = *(rap_http_script_code_pt *) e.ip;
                code((rap_http_script_engine_t *) &e);
            }
            e.ip += sizeof(uintptr_t);

            e.skip = 0;

            continue;
        }

        code = *(rap_http_script_code_pt *) e.ip;
        code((rap_http_script_engine_t *) &e);

        *e.pos++ = ':'; *e.pos++ = ' ';

        while (*(uintptr_t *) e.ip) {
            code = *(rap_http_script_code_pt *) e.ip;
            code((rap_http_script_engine_t *) &e);
        }
        e.ip += sizeof(uintptr_t);

        *e.pos++ = CR; *e.pos++ = LF;
    }

    b->last = e.pos;


    if (plcf->upstream.pass_request_headers) {
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (rap_hash_find(&headers->hash, header[i].hash,
                              header[i].lowcase_key, header[i].key.len))
            {
                continue;
            }

            b->last = rap_copy(b->last, header[i].key.data, header[i].key.len);

            *b->last++ = ':'; *b->last++ = ' ';

            b->last = rap_copy(b->last, header[i].value.data,
                               header[i].value.len);

            *b->last++ = CR; *b->last++ = LF;

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &header[i].key, &header[i].value);
        }
    }


    /* add "\r\n" at the header end */
    *b->last++ = CR; *b->last++ = LF;

    if (plcf->body_values) {
        e.ip = plcf->body_values->elts;
        e.pos = b->last;
        e.skip = 0;

        while (*(uintptr_t *) e.ip) {
            code = *(rap_http_script_code_pt *) e.ip;
            code((rap_http_script_engine_t *) &e);
        }

        b->last = e.pos;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy header:%N\"%*s\"",
                   (size_t) (b->last - b->pos), b->pos);

    if (r->request_body_no_buffering) {

        u->request_bufs = cl;

        if (ctx->internal_chunked) {
            u->output.output_filter = rap_http_proxy_body_output_filter;
            u->output.filter_ctx = r;
        }

    } else if (plcf->body_values == NULL && plcf->upstream.pass_request_body) {

        body = u->request_bufs;
        u->request_bufs = cl;

        while (body) {
            b = rap_alloc_buf(r->pool);
            if (b == NULL) {
                return RAP_ERROR;
            }

            rap_memcpy(b, body->buf, sizeof(rap_buf_t));

            cl->next = rap_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return RAP_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

    } else {
        u->request_bufs = cl;
    }

    b->flush = 1;
    cl->next = NULL;

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_reinit_request(rap_http_request_t *r)
{
    rap_http_proxy_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (ctx == NULL) {
        return RAP_OK;
    }

    ctx->status.code = 0;
    ctx->status.count = 0;
    ctx->status.start = NULL;
    ctx->status.end = NULL;
    ctx->chunked.state = 0;

    r->upstream->process_header = rap_http_proxy_process_status_line;
    r->upstream->pipe->input_filter = rap_http_proxy_copy_filter;
    r->upstream->input_filter = rap_http_proxy_non_buffered_copy_filter;
    r->state = 0;

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_body_output_filter(void *data, rap_chain_t *in)
{
    rap_http_request_t  *r = data;

    off_t                  size;
    u_char                *chunk;
    rap_int_t              rc;
    rap_buf_t             *b;
    rap_chain_t           *out, *cl, *tl, **ll, **fl;
    rap_http_proxy_ctx_t  *ctx;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "proxy output filter");

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (in == NULL) {
        out = in;
        goto out;
    }

    out = NULL;
    ll = &out;

    if (!ctx->header_sent) {
        /* first buffer contains headers, pass it unmodified */

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy output header");

        ctx->header_sent = 1;

        tl = rap_alloc_chain_link(r->pool);
        if (tl == NULL) {
            return RAP_ERROR;
        }

        tl->buf = in->buf;
        *ll = tl;
        ll = &tl->next;

        in = in->next;

        if (in == NULL) {
            tl->next = NULL;
            goto out;
        }
    }

    size = 0;
    cl = in;
    fl = ll;

    for ( ;; ) {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "proxy output chunk: %O", rap_buf_size(cl->buf));

        size += rap_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || rap_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = rap_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return RAP_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    if (size) {
        tl = rap_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return RAP_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            /* the "0000000000000000" is 64-bit hexadecimal string */

            chunk = rap_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
            if (chunk == NULL) {
                return RAP_ERROR;
            }

            b->start = chunk;
            b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
        }

        b->tag = (rap_buf_tag_t) &rap_http_proxy_body_output_filter;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;
        b->last = rap_sprintf(chunk, "%xO" CRLF, size);

        tl->next = *fl;
        *fl = tl;
    }

    if (cl->buf->last_buf) {
        tl = rap_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return RAP_ERROR;
        }

        b = tl->buf;

        b->tag = (rap_buf_tag_t) &rap_http_proxy_body_output_filter;
        b->temporary = 0;
        b->memory = 1;
        b->last_buf = 1;
        b->pos = (u_char *) CRLF "0" CRLF CRLF;
        b->last = b->pos + 7;

        cl->buf->last_buf = 0;

        *ll = tl;

        if (size == 0) {
            b->pos += 2;
        }

    } else if (size > 0) {
        tl = rap_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return RAP_ERROR;
        }

        b = tl->buf;

        b->tag = (rap_buf_tag_t) &rap_http_proxy_body_output_filter;
        b->temporary = 0;
        b->memory = 1;
        b->pos = (u_char *) CRLF;
        b->last = b->pos + 2;

        *ll = tl;

    } else {
        *ll = NULL;
    }

out:

    rc = rap_chain_writer(&r->upstream->writer, out);

    rap_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (rap_buf_tag_t) &rap_http_proxy_body_output_filter);

    return rc;
}


static rap_int_t
rap_http_proxy_process_status_line(rap_http_request_t *r)
{
    size_t                 len;
    rap_int_t              rc;
    rap_http_upstream_t   *u;
    rap_http_proxy_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (ctx == NULL) {
        return RAP_ERROR;
    }

    u = r->upstream;

    rc = rap_http_parse_status_line(r, &u->buffer, &ctx->status);

    if (rc == RAP_AGAIN) {
        return rc;
    }

    if (rc == RAP_ERROR) {

#if (RAP_HTTP_CACHE)

        if (r->cache) {
            r->http_version = RAP_HTTP_VERSION_9;
            return RAP_OK;
        }

#endif

        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "upstream sent no valid HTTP/1.0 header");

#if 0
        if (u->accel) {
            return RAP_HTTP_UPSTREAM_INVALID_HEADER;
        }
#endif

        r->http_version = RAP_HTTP_VERSION_9;
        u->state->status = RAP_HTTP_OK;
        u->headers_in.connection_close = 1;

        return RAP_OK;
    }

    if (u->state && u->state->status == 0) {
        u->state->status = ctx->status.code;
    }

    u->headers_in.status_n = ctx->status.code;

    len = ctx->status.end - ctx->status.start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = rap_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(u->headers_in.status_line.data, ctx->status.start, len);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    if (ctx->status.http_version < RAP_HTTP_VERSION_11) {
        u->headers_in.connection_close = 1;
    }

    u->process_header = rap_http_proxy_process_header;

    return rap_http_proxy_process_header(r);
}


static rap_int_t
rap_http_proxy_process_header(rap_http_request_t *r)
{
    rap_int_t                       rc;
    rap_table_elt_t                *h;
    rap_http_upstream_t            *u;
    rap_http_proxy_ctx_t           *ctx;
    rap_http_upstream_header_t     *hh;
    rap_http_upstream_main_conf_t  *umcf;

    umcf = rap_http_get_module_main_conf(r, rap_http_upstream_module);

    for ( ;; ) {

        rc = rap_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == RAP_OK) {

            /* a header line has been parsed successfully */

            h = rap_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return RAP_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = rap_pnalloc(r->pool,
                               h->key.len + 1 + h->value.len + 1 + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return RAP_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            rap_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            rap_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                rap_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                rap_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = rap_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != RAP_OK) {
                return RAP_ERROR;
            }

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header: \"%V: %V\"",
                           &h->key, &h->value);

            continue;
        }

        if (rc == RAP_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy header done");

            /*
             * if no "Server" and "Date" in header line,
             * then add the special empty headers
             */

            if (r->upstream->headers_in.server == NULL) {
                h = rap_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return RAP_ERROR;
                }

                h->hash = rap_hash(rap_hash(rap_hash(rap_hash(
                                    rap_hash('s', 'e'), 'r'), 'v'), 'e'), 'r');

                rap_str_set(&h->key, "Server");
                rap_str_null(&h->value);
                h->lowcase_key = (u_char *) "server";
            }

            if (r->upstream->headers_in.date == NULL) {
                h = rap_list_push(&r->upstream->headers_in.headers);
                if (h == NULL) {
                    return RAP_ERROR;
                }

                h->hash = rap_hash(rap_hash(rap_hash('d', 'a'), 't'), 'e');

                rap_str_set(&h->key, "Date");
                rap_str_null(&h->value);
                h->lowcase_key = (u_char *) "date";
            }

            /* clear content length if response is chunked */

            u = r->upstream;

            if (u->headers_in.chunked) {
                u->headers_in.content_length_n = -1;
            }

            /*
             * set u->keepalive if response has no body; this allows to keep
             * connections alive in case of r->header_only or X-Accel-Redirect
             */

            ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

            if (u->headers_in.status_n == RAP_HTTP_NO_CONTENT
                || u->headers_in.status_n == RAP_HTTP_NOT_MODIFIED
                || ctx->head
                || (!u->headers_in.chunked
                    && u->headers_in.content_length_n == 0))
            {
                u->keepalive = !u->headers_in.connection_close;
            }

            if (u->headers_in.status_n == RAP_HTTP_SWITCHING_PROTOCOLS) {
                u->keepalive = 0;

                if (r->headers_in.upgrade) {
                    u->upgrade = 1;
                }
            }

            return RAP_OK;
        }

        if (rc == RAP_AGAIN) {
            return RAP_AGAIN;
        }

        /* there was error while a header line parsing */

        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");

        return RAP_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static rap_int_t
rap_http_proxy_input_filter_init(void *data)
{
    rap_http_request_t    *r = data;
    rap_http_upstream_t   *u;
    rap_http_proxy_ctx_t  *ctx;

    u = r->upstream;
    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (ctx == NULL) {
        return RAP_ERROR;
    }

    rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy filter init s:%ui h:%d c:%d l:%O",
                   u->headers_in.status_n, ctx->head, u->headers_in.chunked,
                   u->headers_in.content_length_n);

    /* as per RFC2616, 4.4 Message Length */

    if (u->headers_in.status_n == RAP_HTTP_NO_CONTENT
        || u->headers_in.status_n == RAP_HTTP_NOT_MODIFIED
        || ctx->head)
    {
        /* 1xx, 204, and 304 and replies to HEAD requests */
        /* no 1xx since we don't send Expect and Upgrade */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else if (u->headers_in.chunked) {
        /* chunked */

        u->pipe->input_filter = rap_http_proxy_chunked_filter;
        u->pipe->length = 3; /* "0" LF LF */

        u->input_filter = rap_http_proxy_non_buffered_chunked_filter;
        u->length = 1;

    } else if (u->headers_in.content_length_n == 0) {
        /* empty body: special case as filter won't be called */

        u->pipe->length = 0;
        u->length = 0;
        u->keepalive = !u->headers_in.connection_close;

    } else {
        /* content length or connection close */

        u->pipe->length = u->headers_in.content_length_n;
        u->length = u->headers_in.content_length_n;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_copy_filter(rap_event_pipe_t *p, rap_buf_t *buf)
{
    rap_buf_t           *b;
    rap_chain_t         *cl;
    rap_http_request_t  *r;

    if (buf->pos == buf->last) {
        return RAP_OK;
    }

    cl = rap_chain_get_free_buf(p->pool, &p->free);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    b = cl->buf;

    rap_memcpy(b, buf, sizeof(rap_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;

    if (p->length == -1) {
        return RAP_OK;
    }

    p->length -= b->last - b->pos;

    if (p->length == 0) {
        r = p->input_ctx;
        p->upstream_done = 1;
        r->upstream->keepalive = !r->upstream->headers_in.connection_close;

    } else if (p->length < 0) {
        r = p->input_ctx;
        p->upstream_done = 1;

        rap_log_error(RAP_LOG_WARN, r->connection->log, 0,
                      "upstream sent more data than specified in "
                      "\"Content-Length\" header");
    }

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_chunked_filter(rap_event_pipe_t *p, rap_buf_t *buf)
{
    rap_int_t              rc;
    rap_buf_t             *b, **prev;
    rap_chain_t           *cl;
    rap_http_request_t    *r;
    rap_http_proxy_ctx_t  *ctx;

    if (buf->pos == buf->last) {
        return RAP_OK;
    }

    r = p->input_ctx;
    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (ctx == NULL) {
        return RAP_ERROR;
    }

    b = NULL;
    prev = &buf->shadow;

    for ( ;; ) {

        rc = rap_http_parse_chunked(r, buf, &ctx->chunked);

        if (rc == RAP_OK) {

            /* a chunk has been parsed successfully */

            cl = rap_chain_get_free_buf(p->pool, &p->free);
            if (cl == NULL) {
                return RAP_ERROR;
            }

            b = cl->buf;

            rap_memzero(b, sizeof(rap_buf_t));

            b->pos = buf->pos;
            b->start = buf->start;
            b->end = buf->end;
            b->tag = p->tag;
            b->temporary = 1;
            b->recycled = 1;

            *prev = b;
            prev = &b->shadow;

            if (p->in) {
                *p->last_in = cl;
            } else {
                p->in = cl;
            }
            p->last_in = &cl->next;

            /* STUB */ b->num = buf->num;

            rap_log_debug2(RAP_LOG_DEBUG_EVENT, p->log, 0,
                           "input buf #%d %p", b->num, b->pos);

            if (buf->last - buf->pos >= ctx->chunked.size) {

                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

                continue;
            }

            ctx->chunked.size -= buf->last - buf->pos;
            buf->pos = buf->last;
            b->last = buf->last;

            continue;
        }

        if (rc == RAP_DONE) {

            /* a whole response has been parsed successfully */

            p->upstream_done = 1;
            r->upstream->keepalive = !r->upstream->headers_in.connection_close;

            break;
        }

        if (rc == RAP_AGAIN) {

            /* set p->length, minimal amount of data we want to see */

            p->length = ctx->chunked.length;

            break;
        }

        /* invalid response */

        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid chunked response");

        return RAP_ERROR;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http proxy chunked state %ui, length %O",
                   ctx->chunked.state, p->length);

    if (b) {
        b->shadow = buf;
        b->last_shadow = 1;

        rap_log_debug2(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "input buf %p %z", b->pos, b->last - b->pos);

        return RAP_OK;
    }

    /* there is no data record in the buf, add it to free chain */

    if (rap_event_pipe_add_free_buf(p, buf) != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_non_buffered_copy_filter(void *data, ssize_t bytes)
{
    rap_http_request_t   *r = data;

    rap_buf_t            *b;
    rap_chain_t          *cl, **ll;
    rap_http_upstream_t  *u;

    u = r->upstream;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rap_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    *ll = cl;

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;

    cl->buf->pos = b->last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return RAP_OK;
    }

    u->length -= bytes;

    if (u->length == 0) {
        u->keepalive = !u->headers_in.connection_close;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_non_buffered_chunked_filter(void *data, ssize_t bytes)
{
    rap_http_request_t   *r = data;

    rap_int_t              rc;
    rap_buf_t             *b, *buf;
    rap_chain_t           *cl, **ll;
    rap_http_upstream_t   *u;
    rap_http_proxy_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (ctx == NULL) {
        return RAP_ERROR;
    }

    u = r->upstream;
    buf = &u->buffer;

    buf->pos = buf->last;
    buf->last += bytes;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    for ( ;; ) {

        rc = rap_http_parse_chunked(r, buf, &ctx->chunked);

        if (rc == RAP_OK) {

            /* a chunk has been parsed successfully */

            cl = rap_chain_get_free_buf(r->pool, &u->free_bufs);
            if (cl == NULL) {
                return RAP_ERROR;
            }

            *ll = cl;
            ll = &cl->next;

            b = cl->buf;

            b->flush = 1;
            b->memory = 1;

            b->pos = buf->pos;
            b->tag = u->output.tag;

            if (buf->last - buf->pos >= ctx->chunked.size) {
                buf->pos += (size_t) ctx->chunked.size;
                b->last = buf->pos;
                ctx->chunked.size = 0;

            } else {
                ctx->chunked.size -= buf->last - buf->pos;
                buf->pos = buf->last;
                b->last = buf->last;
            }

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http proxy out buf %p %z",
                           b->pos, b->last - b->pos);

            continue;
        }

        if (rc == RAP_DONE) {

            /* a whole response has been parsed successfully */

            u->keepalive = !u->headers_in.connection_close;
            u->length = 0;

            break;
        }

        if (rc == RAP_AGAIN) {
            break;
        }

        /* invalid response */

        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid chunked response");

        return RAP_ERROR;
    }

    return RAP_OK;
}


static void
rap_http_proxy_abort_request(rap_http_request_t *r)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http proxy request");

    return;
}


static void
rap_http_proxy_finalize_request(rap_http_request_t *r, rap_int_t rc)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http proxy request");

    return;
}


static rap_int_t
rap_http_proxy_host_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_proxy_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->len = ctx->vars.host_header.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.host_header.data;

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_port_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_proxy_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (ctx == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->len = ctx->vars.port.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->vars.port.data;

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_add_x_forwarded_for_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    size_t             len;
    u_char            *p;
    rap_uint_t         i, n;
    rap_table_elt_t  **h;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    n = r->headers_in.x_forwarded_for.nelts;
    h = r->headers_in.x_forwarded_for.elts;

    len = 0;

    for (i = 0; i < n; i++) {
        len += h[i]->value.len + sizeof(", ") - 1;
    }

    if (len == 0) {
        v->len = r->connection->addr_text.len;
        v->data = r->connection->addr_text.data;
        return RAP_OK;
    }

    len += r->connection->addr_text.len;

    p = rap_pnalloc(r->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = len;
    v->data = p;

    for (i = 0; i < n; i++) {
        p = rap_copy(p, h[i]->value.data, h[i]->value.len);
        *p++ = ','; *p++ = ' ';
    }

    rap_memcpy(p, r->connection->addr_text.data, r->connection->addr_text.len);

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_internal_body_length_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_proxy_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (ctx == NULL || ctx->internal_body_length < 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rap_pnalloc(r->pool, RAP_OFF_T_LEN);

    if (v->data == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(v->data, "%O", ctx->internal_body_length) - v->data;

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_internal_chunked_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_proxy_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_proxy_module);

    if (ctx == NULL || !ctx->internal_chunked) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = (u_char *) "chunked";
    v->len = sizeof("chunked") - 1;

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_rewrite_redirect(rap_http_request_t *r, rap_table_elt_t *h,
    size_t prefix)
{
    size_t                      len;
    rap_int_t                   rc;
    rap_uint_t                  i;
    rap_http_proxy_rewrite_t   *pr;
    rap_http_proxy_loc_conf_t  *plcf;

    plcf = rap_http_get_module_loc_conf(r, rap_http_proxy_module);

    pr = plcf->redirects->elts;

    if (pr == NULL) {
        return RAP_DECLINED;
    }

    len = h->value.len - prefix;

    for (i = 0; i < plcf->redirects->nelts; i++) {
        rc = pr[i].handler(r, h, prefix, len, &pr[i]);

        if (rc != RAP_DECLINED) {
            return rc;
        }
    }

    return RAP_DECLINED;
}


static rap_int_t
rap_http_proxy_rewrite_cookie(rap_http_request_t *r, rap_table_elt_t *h)
{
    size_t                      prefix;
    u_char                     *p;
    rap_int_t                   rc, rv;
    rap_http_proxy_loc_conf_t  *plcf;

    p = (u_char *) rap_strchr(h->value.data, ';');
    if (p == NULL) {
        return RAP_DECLINED;
    }

    prefix = p + 1 - h->value.data;

    rv = RAP_DECLINED;

    plcf = rap_http_get_module_loc_conf(r, rap_http_proxy_module);

    if (plcf->cookie_domains) {
        p = rap_strcasestrn(h->value.data + prefix, "domain=", 7 - 1);

        if (p) {
            rc = rap_http_proxy_rewrite_cookie_value(r, h, p + 7,
                                                     plcf->cookie_domains);
            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            if (rc != RAP_DECLINED) {
                rv = rc;
            }
        }
    }

    if (plcf->cookie_paths) {
        p = rap_strcasestrn(h->value.data + prefix, "path=", 5 - 1);

        if (p) {
            rc = rap_http_proxy_rewrite_cookie_value(r, h, p + 5,
                                                     plcf->cookie_paths);
            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            if (rc != RAP_DECLINED) {
                rv = rc;
            }
        }
    }

    return rv;
}


static rap_int_t
rap_http_proxy_rewrite_cookie_value(rap_http_request_t *r, rap_table_elt_t *h,
    u_char *value, rap_array_t *rewrites)
{
    size_t                     len, prefix;
    u_char                    *p;
    rap_int_t                  rc;
    rap_uint_t                 i;
    rap_http_proxy_rewrite_t  *pr;

    prefix = value - h->value.data;

    p = (u_char *) rap_strchr(value, ';');

    len = p ? (size_t) (p - value) : (h->value.len - prefix);

    pr = rewrites->elts;

    for (i = 0; i < rewrites->nelts; i++) {
        rc = pr[i].handler(r, h, prefix, len, &pr[i]);

        if (rc != RAP_DECLINED) {
            return rc;
        }
    }

    return RAP_DECLINED;
}


static rap_int_t
rap_http_proxy_rewrite_complex_handler(rap_http_request_t *r,
    rap_table_elt_t *h, size_t prefix, size_t len, rap_http_proxy_rewrite_t *pr)
{
    rap_str_t  pattern, replacement;

    if (rap_http_complex_value(r, &pr->pattern.complex, &pattern) != RAP_OK) {
        return RAP_ERROR;
    }

    if (pattern.len > len
        || rap_rstrncmp(h->value.data + prefix, pattern.data,
                        pattern.len) != 0)
    {
        return RAP_DECLINED;
    }

    if (rap_http_complex_value(r, &pr->replacement, &replacement) != RAP_OK) {
        return RAP_ERROR;
    }

    return rap_http_proxy_rewrite(r, h, prefix, pattern.len, &replacement);
}


#if (RAP_PCRE)

static rap_int_t
rap_http_proxy_rewrite_regex_handler(rap_http_request_t *r, rap_table_elt_t *h,
    size_t prefix, size_t len, rap_http_proxy_rewrite_t *pr)
{
    rap_str_t  pattern, replacement;

    pattern.len = len;
    pattern.data = h->value.data + prefix;

    if (rap_http_regex_exec(r, pr->pattern.regex, &pattern) != RAP_OK) {
        return RAP_DECLINED;
    }

    if (rap_http_complex_value(r, &pr->replacement, &replacement) != RAP_OK) {
        return RAP_ERROR;
    }

    if (prefix == 0 && h->value.len == len) {
        h->value = replacement;
        return RAP_OK;
    }

    return rap_http_proxy_rewrite(r, h, prefix, len, &replacement);
}

#endif


static rap_int_t
rap_http_proxy_rewrite_domain_handler(rap_http_request_t *r,
    rap_table_elt_t *h, size_t prefix, size_t len, rap_http_proxy_rewrite_t *pr)
{
    u_char     *p;
    rap_str_t   pattern, replacement;

    if (rap_http_complex_value(r, &pr->pattern.complex, &pattern) != RAP_OK) {
        return RAP_ERROR;
    }

    p = h->value.data + prefix;

    if (p[0] == '.') {
        p++;
        prefix++;
        len--;
    }

    if (pattern.len != len || rap_rstrncasecmp(pattern.data, p, len) != 0) {
        return RAP_DECLINED;
    }

    if (rap_http_complex_value(r, &pr->replacement, &replacement) != RAP_OK) {
        return RAP_ERROR;
    }

    return rap_http_proxy_rewrite(r, h, prefix, len, &replacement);
}


static rap_int_t
rap_http_proxy_rewrite(rap_http_request_t *r, rap_table_elt_t *h, size_t prefix,
    size_t len, rap_str_t *replacement)
{
    u_char  *p, *data;
    size_t   new_len;

    new_len = replacement->len + h->value.len - len;

    if (replacement->len > len) {

        data = rap_pnalloc(r->pool, new_len + 1);
        if (data == NULL) {
            return RAP_ERROR;
        }

        p = rap_copy(data, h->value.data, prefix);
        p = rap_copy(p, replacement->data, replacement->len);

        rap_memcpy(p, h->value.data + prefix + len,
                   h->value.len - len - prefix + 1);

        h->value.data = data;

    } else {
        p = rap_copy(h->value.data + prefix, replacement->data,
                     replacement->len);

        rap_memmove(p, h->value.data + prefix + len,
                    h->value.len - len - prefix + 1);
    }

    h->value.len = new_len;

    return RAP_OK;
}


static rap_int_t
rap_http_proxy_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_proxy_vars; v->name.len; v++) {
        var = rap_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static void *
rap_http_proxy_create_main_conf(rap_conf_t *cf)
{
    rap_http_proxy_main_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_proxy_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (RAP_HTTP_CACHE)
    if (rap_array_init(&conf->caches, cf->pool, 4,
                       sizeof(rap_http_file_cache_t *))
        != RAP_OK)
    {
        return NULL;
    }
#endif

    return conf;
}


static void *
rap_http_proxy_create_loc_conf(rap_conf_t *cf)
{
    rap_http_proxy_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_proxy_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.ignore_headers = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.cache_zone = NULL;
     *     conf->upstream.cache_use_stale = 0;
     *     conf->upstream.cache_methods = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.hide_headers_hash = { NULL, 0 };
     *     conf->upstream.store_lengths = NULL;
     *     conf->upstream.store_values = NULL;
     *     conf->upstream.ssl_name = NULL;
     *
     *     conf->method = NULL;
     *     conf->location = NULL;
     *     conf->url = { 0, NULL };
     *     conf->headers_source = NULL;
     *     conf->headers.lengths = NULL;
     *     conf->headers.values = NULL;
     *     conf->headers.hash = { NULL, 0 };
     *     conf->headers_cache.lengths = NULL;
     *     conf->headers_cache.values = NULL;
     *     conf->headers_cache.hash = { NULL, 0 };
     *     conf->body_lengths = NULL;
     *     conf->body_values = NULL;
     *     conf->body_source = { 0, NULL };
     *     conf->redirects = NULL;
     *     conf->ssl = 0;
     *     conf->ssl_protocols = 0;
     *     conf->ssl_ciphers = { 0, NULL };
     *     conf->ssl_trusted_certificate = { 0, NULL };
     *     conf->ssl_crl = { 0, NULL };
     *     conf->ssl_certificate = { 0, NULL };
     *     conf->ssl_certificate_key = { 0, NULL };
     */

    conf->upstream.store = RAP_CONF_UNSET;
    conf->upstream.store_access = RAP_CONF_UNSET_UINT;
    conf->upstream.next_upstream_tries = RAP_CONF_UNSET_UINT;
    conf->upstream.buffering = RAP_CONF_UNSET;
    conf->upstream.request_buffering = RAP_CONF_UNSET;
    conf->upstream.ignore_client_abort = RAP_CONF_UNSET;
    conf->upstream.force_ranges = RAP_CONF_UNSET;

    conf->upstream.local = RAP_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = RAP_CONF_UNSET;

    conf->upstream.connect_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = RAP_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = RAP_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = RAP_CONF_UNSET_SIZE;
    conf->upstream.limit_rate = RAP_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = RAP_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = RAP_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = RAP_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = RAP_CONF_UNSET;
    conf->upstream.pass_request_body = RAP_CONF_UNSET;

#if (RAP_HTTP_CACHE)
    conf->upstream.cache = RAP_CONF_UNSET;
    conf->upstream.cache_min_uses = RAP_CONF_UNSET_UINT;
    conf->upstream.cache_max_range_offset = RAP_CONF_UNSET;
    conf->upstream.cache_bypass = RAP_CONF_UNSET_PTR;
    conf->upstream.no_cache = RAP_CONF_UNSET_PTR;
    conf->upstream.cache_valid = RAP_CONF_UNSET_PTR;
    conf->upstream.cache_lock = RAP_CONF_UNSET;
    conf->upstream.cache_lock_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.cache_lock_age = RAP_CONF_UNSET_MSEC;
    conf->upstream.cache_revalidate = RAP_CONF_UNSET;
    conf->upstream.cache_convert_head = RAP_CONF_UNSET;
    conf->upstream.cache_background_update = RAP_CONF_UNSET;
#endif

    conf->upstream.hide_headers = RAP_CONF_UNSET_PTR;
    conf->upstream.pass_headers = RAP_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = RAP_CONF_UNSET;

#if (RAP_HTTP_SSL)
    conf->upstream.ssl_session_reuse = RAP_CONF_UNSET;
    conf->upstream.ssl_server_name = RAP_CONF_UNSET;
    conf->upstream.ssl_verify = RAP_CONF_UNSET;
    conf->ssl_verify_depth = RAP_CONF_UNSET_UINT;
    conf->ssl_passwords = RAP_CONF_UNSET_PTR;
#endif

    /* "proxy_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->redirect = RAP_CONF_UNSET;
    conf->upstream.change_buffering = 1;

    conf->cookie_domains = RAP_CONF_UNSET_PTR;
    conf->cookie_paths = RAP_CONF_UNSET_PTR;

    conf->http_version = RAP_CONF_UNSET_UINT;

    conf->headers_hash_max_size = RAP_CONF_UNSET_UINT;
    conf->headers_hash_bucket_size = RAP_CONF_UNSET_UINT;

    rap_str_set(&conf->upstream.module, "proxy");

    return conf;
}


static char *
rap_http_proxy_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_proxy_loc_conf_t *prev = parent;
    rap_http_proxy_loc_conf_t *conf = child;

    u_char                     *p;
    size_t                      size;
    rap_int_t                   rc;
    rap_hash_init_t             hash;
    rap_http_core_loc_conf_t   *clcf;
    rap_http_proxy_rewrite_t   *pr;
    rap_http_script_compile_t   sc;

#if (RAP_HTTP_CACHE)

    if (conf->upstream.store > 0) {
        conf->upstream.cache = 0;
    }

    if (conf->upstream.cache > 0) {
        conf->upstream.store = 0;
    }

#endif

    if (conf->upstream.store == RAP_CONF_UNSET) {
        rap_conf_merge_value(conf->upstream.store,
                              prev->upstream.store, 0);

        conf->upstream.store_lengths = prev->upstream.store_lengths;
        conf->upstream.store_values = prev->upstream.store_values;
    }

    rap_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    rap_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    rap_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    rap_conf_merge_value(conf->upstream.request_buffering,
                              prev->upstream.request_buffering, 1);

    rap_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    rap_conf_merge_value(conf->upstream.force_ranges,
                              prev->upstream.force_ranges, 0);

    rap_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    rap_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    rap_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    rap_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    rap_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) rap_pagesize);

    rap_conf_merge_size_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, 0);

    rap_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, rap_pagesize);

    if (conf->upstream.bufs.num < 2) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"proxy_buffers\"");
        return RAP_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    rap_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              RAP_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == RAP_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
                                         conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be equal to or greater than "
             "the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return RAP_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
             "\"proxy_busy_buffers_size\" must be less than "
             "the size of all \"proxy_buffers\" minus one buffer");

        return RAP_CONF_ERROR;
    }


    rap_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              RAP_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == RAP_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
                                      conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
             "\"proxy_temp_file_write_size\" must be equal to or greater "
             "than the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return RAP_CONF_ERROR;
    }

    rap_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              RAP_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == RAP_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
                                        conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
             "\"proxy_max_temp_file_size\" must be equal to zero to disable "
             "temporary files usage or must be equal to or greater than "
             "the maximum of the value of \"proxy_buffer_size\" and "
             "one of the \"proxy_buffers\"");

        return RAP_CONF_ERROR;
    }


    rap_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                              prev->upstream.ignore_headers,
                              RAP_CONF_BITMASK_SET);


    rap_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (RAP_CONF_BITMASK_SET
                               |RAP_HTTP_UPSTREAM_FT_ERROR
                               |RAP_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & RAP_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = RAP_CONF_BITMASK_SET
                                       |RAP_HTTP_UPSTREAM_FT_OFF;
    }

    if (rap_conf_merge_path_value(cf, &conf->upstream.temp_path,
                              prev->upstream.temp_path,
                              &rap_http_proxy_temp_path)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }


#if (RAP_HTTP_CACHE)

    if (conf->upstream.cache == RAP_CONF_UNSET) {
        rap_conf_merge_value(conf->upstream.cache,
                              prev->upstream.cache, 0);

        conf->upstream.cache_zone = prev->upstream.cache_zone;
        conf->upstream.cache_value = prev->upstream.cache_value;
    }

    if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
        rap_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache_zone;

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"proxy_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return RAP_CONF_ERROR;
    }

    rap_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    rap_conf_merge_off_value(conf->upstream.cache_max_range_offset,
                              prev->upstream.cache_max_range_offset,
                              RAP_MAX_OFF_T_VALUE);

    rap_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (RAP_CONF_BITMASK_SET
                               |RAP_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & RAP_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = RAP_CONF_BITMASK_SET
                                         |RAP_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_use_stale & RAP_HTTP_UPSTREAM_FT_ERROR) {
        conf->upstream.cache_use_stale |= RAP_HTTP_UPSTREAM_FT_NOLIVE;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= RAP_HTTP_GET|RAP_HTTP_HEAD;

    rap_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    rap_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    rap_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

    rap_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    rap_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

    rap_conf_merge_msec_value(conf->upstream.cache_lock_age,
                              prev->upstream.cache_lock_age, 5000);

    rap_conf_merge_value(conf->upstream.cache_revalidate,
                              prev->upstream.cache_revalidate, 0);

    rap_conf_merge_value(conf->upstream.cache_convert_head,
                              prev->upstream.cache_convert_head, 1);

    rap_conf_merge_value(conf->upstream.cache_background_update,
                              prev->upstream.cache_background_update, 0);

#endif

    if (conf->method == NULL) {
        conf->method = prev->method;
    }

    rap_conf_merge_value(conf->upstream.pass_request_headers,
                              prev->upstream.pass_request_headers, 1);
    rap_conf_merge_value(conf->upstream.pass_request_body,
                              prev->upstream.pass_request_body, 1);

    rap_conf_merge_value(conf->upstream.intercept_errors,
                              prev->upstream.intercept_errors, 0);

#if (RAP_HTTP_SSL)

    rap_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);

    rap_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                                 (RAP_CONF_BITMASK_SET|RAP_SSL_TLSv1
                                  |RAP_SSL_TLSv1_1|RAP_SSL_TLSv1_2));

    rap_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    if (conf->upstream.ssl_name == NULL) {
        conf->upstream.ssl_name = prev->upstream.ssl_name;
    }

    rap_conf_merge_value(conf->upstream.ssl_server_name,
                              prev->upstream.ssl_server_name, 0);
    rap_conf_merge_value(conf->upstream.ssl_verify,
                              prev->upstream.ssl_verify, 0);
    rap_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    rap_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");
    rap_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    rap_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");
    rap_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");
    rap_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl && rap_http_proxy_set_ssl(cf, conf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

#endif

    rap_conf_merge_value(conf->redirect, prev->redirect, 1);

    if (conf->redirect) {

        if (conf->redirects == NULL) {
            conf->redirects = prev->redirects;
        }

        if (conf->redirects == NULL && conf->url.data) {

            conf->redirects = rap_array_create(cf->pool, 1,
                                             sizeof(rap_http_proxy_rewrite_t));
            if (conf->redirects == NULL) {
                return RAP_CONF_ERROR;
            }

            pr = rap_array_push(conf->redirects);
            if (pr == NULL) {
                return RAP_CONF_ERROR;
            }

            rap_memzero(&pr->pattern.complex,
                        sizeof(rap_http_complex_value_t));

            rap_memzero(&pr->replacement, sizeof(rap_http_complex_value_t));

            pr->handler = rap_http_proxy_rewrite_complex_handler;

            if (conf->vars.uri.len) {
                pr->pattern.complex.value = conf->url;
                pr->replacement.value = conf->location;

            } else {
                pr->pattern.complex.value.len = conf->url.len
                                                + sizeof("/") - 1;

                p = rap_pnalloc(cf->pool, pr->pattern.complex.value.len);
                if (p == NULL) {
                    return RAP_CONF_ERROR;
                }

                pr->pattern.complex.value.data = p;

                p = rap_cpymem(p, conf->url.data, conf->url.len);
                *p = '/';

                rap_str_set(&pr->replacement.value, "/");
            }
        }
    }

    rap_conf_merge_ptr_value(conf->cookie_domains, prev->cookie_domains, NULL);

    rap_conf_merge_ptr_value(conf->cookie_paths, prev->cookie_paths, NULL);

    rap_conf_merge_uint_value(conf->http_version, prev->http_version,
                              RAP_HTTP_VERSION_10);

    rap_conf_merge_uint_value(conf->headers_hash_max_size,
                              prev->headers_hash_max_size, 512);

    rap_conf_merge_uint_value(conf->headers_hash_bucket_size,
                              prev->headers_hash_bucket_size, 64);

    conf->headers_hash_bucket_size = rap_align(conf->headers_hash_bucket_size,
                                               rap_cacheline_size);

    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";

    if (rap_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, rap_http_proxy_hide_headers, &hash)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->proxy_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->location = prev->location;
        conf->vars = prev->vars;

        conf->proxy_lengths = prev->proxy_lengths;
        conf->proxy_values = prev->proxy_values;

#if (RAP_HTTP_SSL)
        conf->upstream.ssl = prev->upstream.ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->proxy_lengths))
    {
        clcf->handler = rap_http_proxy_handler;
    }

    if (conf->body_source.data == NULL) {
        conf->body_flushes = prev->body_flushes;
        conf->body_source = prev->body_source;
        conf->body_lengths = prev->body_lengths;
        conf->body_values = prev->body_values;
    }

    if (conf->body_source.data && conf->body_lengths == NULL) {

        rap_memzero(&sc, sizeof(rap_http_script_compile_t));

        sc.cf = cf;
        sc.source = &conf->body_source;
        sc.flushes = &conf->body_flushes;
        sc.lengths = &conf->body_lengths;
        sc.values = &conf->body_values;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    if (conf->headers_source == NULL) {
        conf->headers = prev->headers;
#if (RAP_HTTP_CACHE)
        conf->headers_cache = prev->headers_cache;
#endif
        conf->headers_source = prev->headers_source;
    }

    rc = rap_http_proxy_init_headers(cf, conf, &conf->headers,
                                     rap_http_proxy_headers);
    if (rc != RAP_OK) {
        return RAP_CONF_ERROR;
    }

#if (RAP_HTTP_CACHE)

    if (conf->upstream.cache) {
        rc = rap_http_proxy_init_headers(cf, conf, &conf->headers_cache,
                                         rap_http_proxy_cache_headers);
        if (rc != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

#endif

    /*
     * special handling to preserve conf->headers in the "http" section
     * to inherit it to all servers
     */

    if (prev->headers.hash.buckets == NULL
        && conf->headers_source == prev->headers_source)
    {
        prev->headers = conf->headers;
#if (RAP_HTTP_CACHE)
        prev->headers_cache = conf->headers_cache;
#endif
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_proxy_init_headers(rap_conf_t *cf, rap_http_proxy_loc_conf_t *conf,
    rap_http_proxy_headers_t *headers, rap_keyval_t *default_headers)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    rap_uint_t                    i;
    rap_array_t                   headers_names, headers_merged;
    rap_keyval_t                 *src, *s, *h;
    rap_hash_key_t               *hk;
    rap_hash_init_t               hash;
    rap_http_script_compile_t     sc;
    rap_http_script_copy_code_t  *copy;

    if (headers->hash.buckets) {
        return RAP_OK;
    }

    if (rap_array_init(&headers_names, cf->temp_pool, 4, sizeof(rap_hash_key_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (rap_array_init(&headers_merged, cf->temp_pool, 4, sizeof(rap_keyval_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    headers->lengths = rap_array_create(cf->pool, 64, 1);
    if (headers->lengths == NULL) {
        return RAP_ERROR;
    }

    headers->values = rap_array_create(cf->pool, 512, 1);
    if (headers->values == NULL) {
        return RAP_ERROR;
    }

    if (conf->headers_source) {

        src = conf->headers_source->elts;
        for (i = 0; i < conf->headers_source->nelts; i++) {

            s = rap_array_push(&headers_merged);
            if (s == NULL) {
                return RAP_ERROR;
            }

            *s = src[i];
        }
    }

    h = default_headers;

    while (h->key.len) {

        src = headers_merged.elts;
        for (i = 0; i < headers_merged.nelts; i++) {
            if (rap_strcasecmp(h->key.data, src[i].key.data) == 0) {
                goto next;
            }
        }

        s = rap_array_push(&headers_merged);
        if (s == NULL) {
            return RAP_ERROR;
        }

        *s = *h;

    next:

        h++;
    }


    src = headers_merged.elts;
    for (i = 0; i < headers_merged.nelts; i++) {

        hk = rap_array_push(&headers_names);
        if (hk == NULL) {
            return RAP_ERROR;
        }

        hk->key = src[i].key;
        hk->key_hash = rap_hash_key_lc(src[i].key.data, src[i].key.len);
        hk->value = (void *) 1;

        if (src[i].value.len == 0) {
            continue;
        }

        copy = rap_array_push_n(headers->lengths,
                                sizeof(rap_http_script_copy_code_t));
        if (copy == NULL) {
            return RAP_ERROR;
        }

        copy->code = (rap_http_script_code_pt) (void *)
                                                 rap_http_script_copy_len_code;
        copy->len = src[i].key.len;

        size = (sizeof(rap_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = rap_array_push_n(headers->values, size);
        if (copy == NULL) {
            return RAP_ERROR;
        }

        copy->code = rap_http_script_copy_code;
        copy->len = src[i].key.len;

        p = (u_char *) copy + sizeof(rap_http_script_copy_code_t);
        rap_memcpy(p, src[i].key.data, src[i].key.len);

        rap_memzero(&sc, sizeof(rap_http_script_compile_t));

        sc.cf = cf;
        sc.source = &src[i].value;
        sc.flushes = &headers->flushes;
        sc.lengths = &headers->lengths;
        sc.values = &headers->values;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_ERROR;
        }

        code = rap_array_push_n(headers->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;

        code = rap_array_push_n(headers->values, sizeof(uintptr_t));
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = rap_array_push_n(headers->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return RAP_ERROR;
    }

    *code = (uintptr_t) NULL;


    hash.hash = &headers->hash;
    hash.key = rap_hash_key_lc;
    hash.max_size = conf->headers_hash_max_size;
    hash.bucket_size = conf->headers_hash_bucket_size;
    hash.name = "proxy_headers_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return rap_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
rap_http_proxy_pass(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_proxy_loc_conf_t *plcf = conf;

    size_t                      add;
    u_short                     port;
    rap_str_t                  *value, *url;
    rap_url_t                   u;
    rap_uint_t                  n;
    rap_http_core_loc_conf_t   *clcf;
    rap_http_script_compile_t   sc;

    if (plcf->upstream.upstream || plcf->proxy_lengths) {
        return "is duplicate";
    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);

    clcf->handler = rap_http_proxy_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    value = cf->args->elts;

    url = &value[1];

    n = rap_http_script_variables_count(url);

    if (n) {

        rap_memzero(&sc, sizeof(rap_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &plcf->proxy_lengths;
        sc.values = &plcf->proxy_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

#if (RAP_HTTP_SSL)
        plcf->ssl = 1;
#endif

        return RAP_CONF_OK;
    }

    if (rap_strncasecmp(url->data, (u_char *) "http://", 7) == 0) {
        add = 7;
        port = 80;

    } else if (rap_strncasecmp(url->data, (u_char *) "https://", 8) == 0) {

#if (RAP_HTTP_SSL)
        plcf->ssl = 1;

        add = 8;
        port = 443;
#else
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "https protocol requires SSL support");
        return RAP_CONF_ERROR;
#endif

    } else {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "invalid URL prefix");
        return RAP_CONF_ERROR;
    }

    rap_memzero(&u, sizeof(rap_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.default_port = port;
    u.uri_part = 1;
    u.no_resolve = 1;

    plcf->upstream.upstream = rap_http_upstream_add(cf, &u, 0);
    if (plcf->upstream.upstream == NULL) {
        return RAP_CONF_ERROR;
    }

    plcf->vars.schema.len = add;
    plcf->vars.schema.data = url->data;
    plcf->vars.key_start = plcf->vars.schema;

    rap_http_proxy_set_vars(&u, &plcf->vars);

    plcf->location = clcf->name;

    if (clcf->named
#if (RAP_PCRE)
        || clcf->regex
#endif
        || clcf->noname)
    {
        if (plcf->vars.uri.len) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "\"proxy_pass\" cannot have URI part in "
                               "location given by regular expression, "
                               "or inside named location, "
                               "or inside \"if\" statement, "
                               "or inside \"limit_except\" block");
            return RAP_CONF_ERROR;
        }

        plcf->location.len = 0;
    }

    plcf->url = *url;

    return RAP_CONF_OK;
}


static char *
rap_http_proxy_redirect(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_proxy_loc_conf_t *plcf = conf;

    u_char                            *p;
    rap_str_t                         *value;
    rap_http_proxy_rewrite_t          *pr;
    rap_http_compile_complex_value_t   ccv;

    if (plcf->redirect == 0) {
        return RAP_CONF_OK;
    }

    plcf->redirect = 1;

    value = cf->args->elts;

    if (cf->args->nelts == 2) {
        if (rap_strcmp(value[1].data, "off") == 0) {
            plcf->redirect = 0;
            plcf->redirects = NULL;
            return RAP_CONF_OK;
        }

        if (rap_strcmp(value[1].data, "false") == 0) {
            rap_conf_log_error(RAP_LOG_ERR, cf, 0,
                           "invalid parameter \"false\", use \"off\" instead");
            plcf->redirect = 0;
            plcf->redirects = NULL;
            return RAP_CONF_OK;
        }

        if (rap_strcmp(value[1].data, "default") != 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }
    }

    if (plcf->redirects == NULL) {
        plcf->redirects = rap_array_create(cf->pool, 1,
                                           sizeof(rap_http_proxy_rewrite_t));
        if (plcf->redirects == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    pr = rap_array_push(plcf->redirects);
    if (pr == NULL) {
        return RAP_CONF_ERROR;
    }

    if (rap_strcmp(value[1].data, "default") == 0) {
        if (plcf->proxy_lengths) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "\"proxy_redirect default\" cannot be used "
                               "with \"proxy_pass\" directive with variables");
            return RAP_CONF_ERROR;
        }

        if (plcf->url.data == NULL) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "\"proxy_redirect default\" should be placed "
                               "after the \"proxy_pass\" directive");
            return RAP_CONF_ERROR;
        }

        pr->handler = rap_http_proxy_rewrite_complex_handler;

        rap_memzero(&pr->pattern.complex, sizeof(rap_http_complex_value_t));

        rap_memzero(&pr->replacement, sizeof(rap_http_complex_value_t));

        if (plcf->vars.uri.len) {
            pr->pattern.complex.value = plcf->url;
            pr->replacement.value = plcf->location;

        } else {
            pr->pattern.complex.value.len = plcf->url.len + sizeof("/") - 1;

            p = rap_pnalloc(cf->pool, pr->pattern.complex.value.len);
            if (p == NULL) {
                return RAP_CONF_ERROR;
            }

            pr->pattern.complex.value.data = p;

            p = rap_cpymem(p, plcf->url.data, plcf->url.len);
            *p = '/';

            rap_str_set(&pr->replacement.value, "/");
        }

        return RAP_CONF_OK;
    }


    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (value[1].data[0] == '*') {
            value[1].len--;
            value[1].data++;

            if (rap_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

        } else {
            if (rap_http_proxy_rewrite_regex(cf, pr, &value[1], 0) != RAP_OK) {
                return RAP_CONF_ERROR;
            }
        }

    } else {

        rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

        pr->handler = rap_http_proxy_rewrite_complex_handler;
    }


    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_proxy_cookie_domain(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_proxy_loc_conf_t *plcf = conf;

    rap_str_t                         *value;
    rap_http_proxy_rewrite_t          *pr;
    rap_http_compile_complex_value_t   ccv;

    if (plcf->cookie_domains == NULL) {
        return RAP_CONF_OK;
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        if (rap_strcmp(value[1].data, "off") == 0) {
            plcf->cookie_domains = NULL;
            return RAP_CONF_OK;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return RAP_CONF_ERROR;
    }

    if (plcf->cookie_domains == RAP_CONF_UNSET_PTR) {
        plcf->cookie_domains = rap_array_create(cf->pool, 1,
                                     sizeof(rap_http_proxy_rewrite_t));
        if (plcf->cookie_domains == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    pr = rap_array_push(plcf->cookie_domains);
    if (pr == NULL) {
        return RAP_CONF_ERROR;
    }

    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (rap_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

    } else {

        if (value[1].data[0] == '.') {
            value[1].len--;
            value[1].data++;
        }

        rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

        pr->handler = rap_http_proxy_rewrite_domain_handler;

        if (value[2].data[0] == '.') {
            value[2].len--;
            value[2].data++;
        }
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_proxy_cookie_path(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_proxy_loc_conf_t *plcf = conf;

    rap_str_t                         *value;
    rap_http_proxy_rewrite_t          *pr;
    rap_http_compile_complex_value_t   ccv;

    if (plcf->cookie_paths == NULL) {
        return RAP_CONF_OK;
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        if (rap_strcmp(value[1].data, "off") == 0) {
            plcf->cookie_paths = NULL;
            return RAP_CONF_OK;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return RAP_CONF_ERROR;
    }

    if (plcf->cookie_paths == RAP_CONF_UNSET_PTR) {
        plcf->cookie_paths = rap_array_create(cf->pool, 1,
                                     sizeof(rap_http_proxy_rewrite_t));
        if (plcf->cookie_paths == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    pr = rap_array_push(plcf->cookie_paths);
    if (pr == NULL) {
        return RAP_CONF_ERROR;
    }

    if (value[1].data[0] == '~') {
        value[1].len--;
        value[1].data++;

        if (value[1].data[0] == '*') {
            value[1].len--;
            value[1].data++;

            if (rap_http_proxy_rewrite_regex(cf, pr, &value[1], 1) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

        } else {
            if (rap_http_proxy_rewrite_regex(cf, pr, &value[1], 0) != RAP_OK) {
                return RAP_CONF_ERROR;
            }
        }

    } else {

        rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[1];
        ccv.complex_value = &pr->pattern.complex;

        if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

        pr->handler = rap_http_proxy_rewrite_complex_handler;
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &pr->replacement;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_proxy_rewrite_regex(rap_conf_t *cf, rap_http_proxy_rewrite_t *pr,
    rap_str_t *regex, rap_uint_t caseless)
{
#if (RAP_PCRE)
    u_char               errstr[RAP_MAX_CONF_ERRSTR];
    rap_regex_compile_t  rc;

    rap_memzero(&rc, sizeof(rap_regex_compile_t));

    rc.pattern = *regex;
    rc.err.len = RAP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (caseless) {
        rc.options = RAP_REGEX_CASELESS;
    }

    pr->pattern.regex = rap_http_regex_compile(cf, &rc);
    if (pr->pattern.regex == NULL) {
        return RAP_ERROR;
    }

    pr->handler = rap_http_proxy_rewrite_regex_handler;

    return RAP_OK;

#else

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "using regex \"%V\" requires PCRE library", regex);
    return RAP_ERROR;

#endif
}


static char *
rap_http_proxy_store(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_proxy_loc_conf_t *plcf = conf;

    rap_str_t                  *value;
    rap_http_script_compile_t   sc;

    if (plcf->upstream.store != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {
        plcf->upstream.store = 0;
        return RAP_CONF_OK;
    }

#if (RAP_HTTP_CACHE)
    if (plcf->upstream.cache > 0) {
        return "is incompatible with \"proxy_cache\"";
    }
#endif

    plcf->upstream.store = 1;

    if (rap_strcmp(value[1].data, "on") == 0) {
        return RAP_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    rap_memzero(&sc, sizeof(rap_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &plcf->upstream.store_lengths;
    sc.values = &plcf->upstream.store_values;
    sc.variables = rap_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (rap_http_script_compile(&sc) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


#if (RAP_HTTP_CACHE)

static char *
rap_http_proxy_cache(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_proxy_loc_conf_t *plcf = conf;

    rap_str_t                         *value;
    rap_http_complex_value_t           cv;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (plcf->upstream.cache != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    if (rap_strcmp(value[1].data, "off") == 0) {
        plcf->upstream.cache = 0;
        return RAP_CONF_OK;
    }

    if (plcf->upstream.store > 0) {
        return "is incompatible with \"proxy_store\"";
    }

    plcf->upstream.cache = 1;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        plcf->upstream.cache_value = rap_palloc(cf->pool,
                                             sizeof(rap_http_complex_value_t));
        if (plcf->upstream.cache_value == NULL) {
            return RAP_CONF_ERROR;
        }

        *plcf->upstream.cache_value = cv;

        return RAP_CONF_OK;
    }

    plcf->upstream.cache_zone = rap_shared_memory_add(cf, &value[1], 0,
                                                      &rap_http_proxy_module);
    if (plcf->upstream.cache_zone == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_proxy_cache_key(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_proxy_loc_conf_t *plcf = conf;

    rap_str_t                         *value;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (plcf->cache_key.value.data) {
        return "is duplicate";
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &plcf->cache_key;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}

#endif


#if (RAP_HTTP_SSL)

static char *
rap_http_proxy_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_proxy_loc_conf_t *plcf = conf;

    rap_str_t  *value;

    if (plcf->ssl_passwords != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    plcf->ssl_passwords = rap_ssl_read_password_file(cf, &value[1]);

    if (plcf->ssl_passwords == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}

#endif


static char *
rap_http_proxy_lowat_check(rap_conf_t *cf, void *post, void *data)
{
#if (RAP_FREEBSD)
    ssize_t *np = data;

    if ((u_long) *np >= rap_freebsd_net_inet_tcp_sendspace) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "\"proxy_send_lowat\" must be less than %d "
                           "(sysctl net.inet.tcp.sendspace)",
                           rap_freebsd_net_inet_tcp_sendspace);

        return RAP_CONF_ERROR;
    }

#elif !(RAP_HAVE_SO_SNDLOWAT)
    ssize_t *np = data;

    rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                       "\"proxy_send_lowat\" is not supported, ignored");

    *np = 0;

#endif

    return RAP_CONF_OK;
}


#if (RAP_HTTP_SSL)

static rap_int_t
rap_http_proxy_set_ssl(rap_conf_t *cf, rap_http_proxy_loc_conf_t *plcf)
{
    rap_pool_cleanup_t  *cln;

    plcf->upstream.ssl = rap_pcalloc(cf->pool, sizeof(rap_ssl_t));
    if (plcf->upstream.ssl == NULL) {
        return RAP_ERROR;
    }

    plcf->upstream.ssl->log = cf->log;

    if (rap_ssl_create(plcf->upstream.ssl, plcf->ssl_protocols, NULL)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rap_ssl_cleanup_ctx(plcf->upstream.ssl);
        return RAP_ERROR;
    }

    cln->handler = rap_ssl_cleanup_ctx;
    cln->data = plcf->upstream.ssl;

    if (plcf->ssl_certificate.len) {

        if (plcf->ssl_certificate_key.len == 0) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no \"proxy_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &plcf->ssl_certificate);
            return RAP_ERROR;
        }

        if (rap_ssl_certificate(cf, plcf->upstream.ssl, &plcf->ssl_certificate,
                                &plcf->ssl_certificate_key, plcf->ssl_passwords)
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    if (rap_ssl_ciphers(cf, plcf->upstream.ssl, &plcf->ssl_ciphers, 0)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (plcf->upstream.ssl_verify) {
        if (plcf->ssl_trusted_certificate.len == 0) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no proxy_ssl_trusted_certificate for proxy_ssl_verify");
            return RAP_ERROR;
        }

        if (rap_ssl_trusted_certificate(cf, plcf->upstream.ssl,
                                        &plcf->ssl_trusted_certificate,
                                        plcf->ssl_verify_depth)
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        if (rap_ssl_crl(cf, plcf->upstream.ssl, &plcf->ssl_crl) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    if (rap_ssl_client_session_cache(cf, plcf->upstream.ssl,
                                     plcf->upstream.ssl_session_reuse)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    return RAP_OK;
}

#endif


static void
rap_http_proxy_set_vars(rap_url_t *u, rap_http_proxy_vars_t *v)
{
    if (u->family != AF_UNIX) {

        if (u->no_port || u->port == u->default_port) {

            v->host_header = u->host;

            if (u->default_port == 80) {
                rap_str_set(&v->port, "80");

            } else {
                rap_str_set(&v->port, "443");
            }

        } else {
            v->host_header.len = u->host.len + 1 + u->port_text.len;
            v->host_header.data = u->host.data;
            v->port = u->port_text;
        }

        v->key_start.len += v->host_header.len;

    } else {
        rap_str_set(&v->host_header, "localhost");
        rap_str_null(&v->port);
        v->key_start.len += sizeof("unix:") - 1 + u->host.len + 1;
    }

    v->uri = u->uri;
}
