
/*
 * Copyright (C) Unbit S.a.s. 2009-2010
 * Copyright (C) 2008 Manlio Perillo (manlio.perillo@gmail.com)
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_array_t                caches;  /* rap_http_file_cache_t * */
} rap_http_uwsgi_main_conf_t;


typedef struct {
    rap_array_t               *flushes;
    rap_array_t               *lengths;
    rap_array_t               *values;
    rap_uint_t                 number;
    rap_hash_t                 hash;
} rap_http_uwsgi_params_t;


typedef struct {
    rap_http_upstream_conf_t   upstream;

    rap_http_uwsgi_params_t    params;
#if (RAP_HTTP_CACHE)
    rap_http_uwsgi_params_t    params_cache;
#endif
    rap_array_t               *params_source;

    rap_array_t               *uwsgi_lengths;
    rap_array_t               *uwsgi_values;

#if (RAP_HTTP_CACHE)
    rap_http_complex_value_t   cache_key;
#endif

    rap_str_t                  uwsgi_string;

    rap_uint_t                 modifier1;
    rap_uint_t                 modifier2;

#if (RAP_HTTP_SSL)
    rap_uint_t                 ssl;
    rap_uint_t                 ssl_protocols;
    rap_str_t                  ssl_ciphers;
    rap_uint_t                 ssl_verify_depth;
    rap_str_t                  ssl_trusted_certificate;
    rap_str_t                  ssl_crl;
    rap_str_t                  ssl_certificate;
    rap_str_t                  ssl_certificate_key;
    rap_array_t               *ssl_passwords;
#endif
} rap_http_uwsgi_loc_conf_t;


static rap_int_t rap_http_uwsgi_eval(rap_http_request_t *r,
    rap_http_uwsgi_loc_conf_t *uwcf);
static rap_int_t rap_http_uwsgi_create_request(rap_http_request_t *r);
static rap_int_t rap_http_uwsgi_reinit_request(rap_http_request_t *r);
static rap_int_t rap_http_uwsgi_process_status_line(rap_http_request_t *r);
static rap_int_t rap_http_uwsgi_process_header(rap_http_request_t *r);
static void rap_http_uwsgi_abort_request(rap_http_request_t *r);
static void rap_http_uwsgi_finalize_request(rap_http_request_t *r,
    rap_int_t rc);

static void *rap_http_uwsgi_create_main_conf(rap_conf_t *cf);
static void *rap_http_uwsgi_create_loc_conf(rap_conf_t *cf);
static char *rap_http_uwsgi_merge_loc_conf(rap_conf_t *cf, void *parent,
    void *child);
static rap_int_t rap_http_uwsgi_init_params(rap_conf_t *cf,
    rap_http_uwsgi_loc_conf_t *conf, rap_http_uwsgi_params_t *params,
    rap_keyval_t *default_params);

static char *rap_http_uwsgi_pass(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_uwsgi_store(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);

#if (RAP_HTTP_CACHE)
static rap_int_t rap_http_uwsgi_create_key(rap_http_request_t *r);
static char *rap_http_uwsgi_cache(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_uwsgi_cache_key(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
#endif

#if (RAP_HTTP_SSL)
static char *rap_http_uwsgi_ssl_password_file(rap_conf_t *cf,
    rap_command_t *cmd, void *conf);
static rap_int_t rap_http_uwsgi_set_ssl(rap_conf_t *cf,
    rap_http_uwsgi_loc_conf_t *uwcf);
#endif


static rap_conf_num_bounds_t  rap_http_uwsgi_modifier_bounds = {
    rap_conf_check_num_bounds, 0, 255
};


static rap_conf_bitmask_t rap_http_uwsgi_next_upstream_masks[] = {
    { rap_string("error"), RAP_HTTP_UPSTREAM_FT_ERROR },
    { rap_string("timeout"), RAP_HTTP_UPSTREAM_FT_TIMEOUT },
    { rap_string("invalid_header"), RAP_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { rap_string("non_idempotent"), RAP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { rap_string("http_500"), RAP_HTTP_UPSTREAM_FT_HTTP_500 },
    { rap_string("http_503"), RAP_HTTP_UPSTREAM_FT_HTTP_503 },
    { rap_string("http_403"), RAP_HTTP_UPSTREAM_FT_HTTP_403 },
    { rap_string("http_404"), RAP_HTTP_UPSTREAM_FT_HTTP_404 },
    { rap_string("http_429"), RAP_HTTP_UPSTREAM_FT_HTTP_429 },
    { rap_string("updating"), RAP_HTTP_UPSTREAM_FT_UPDATING },
    { rap_string("off"), RAP_HTTP_UPSTREAM_FT_OFF },
    { rap_null_string, 0 }
};


#if (RAP_HTTP_SSL)

static rap_conf_bitmask_t  rap_http_uwsgi_ssl_protocols[] = {
    { rap_string("SSLv2"), RAP_SSL_SSLv2 },
    { rap_string("SSLv3"), RAP_SSL_SSLv3 },
    { rap_string("TLSv1"), RAP_SSL_TLSv1 },
    { rap_string("TLSv1.1"), RAP_SSL_TLSv1_1 },
    { rap_string("TLSv1.2"), RAP_SSL_TLSv1_2 },
    { rap_string("TLSv1.3"), RAP_SSL_TLSv1_3 },
    { rap_null_string, 0 }
};

#endif


rap_module_t  rap_http_uwsgi_module;


static rap_command_t rap_http_uwsgi_commands[] = {

    { rap_string("uwsgi_pass"),
      RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF|RAP_CONF_TAKE1,
      rap_http_uwsgi_pass,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("uwsgi_modifier1"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, modifier1),
      &rap_http_uwsgi_modifier_bounds },

    { rap_string("uwsgi_modifier2"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, modifier2),
      &rap_http_uwsgi_modifier_bounds },

    { rap_string("uwsgi_store"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_uwsgi_store,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("uwsgi_store_access"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE123,
      rap_conf_set_access_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.store_access),
      NULL },

    { rap_string("uwsgi_buffering"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.buffering),
      NULL },

    { rap_string("uwsgi_request_buffering"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.request_buffering),
      NULL },

    { rap_string("uwsgi_ignore_client_abort"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { rap_string("uwsgi_bind"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_upstream_bind_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.local),
      NULL },

    { rap_string("uwsgi_socket_keepalive"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { rap_string("uwsgi_connect_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.connect_timeout),
      NULL },

    { rap_string("uwsgi_send_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.send_timeout),
      NULL },

    { rap_string("uwsgi_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.buffer_size),
      NULL },

    { rap_string("uwsgi_pass_request_headers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { rap_string("uwsgi_pass_request_body"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.pass_request_body),
      NULL },

    { rap_string("uwsgi_intercept_errors"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.intercept_errors),
      NULL },

    { rap_string("uwsgi_read_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.read_timeout),
      NULL },

    { rap_string("uwsgi_buffers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_conf_set_bufs_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.bufs),
      NULL },

    { rap_string("uwsgi_busy_buffers_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { rap_string("uwsgi_force_ranges"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.force_ranges),
      NULL },

    { rap_string("uwsgi_limit_rate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.limit_rate),
      NULL },

#if (RAP_HTTP_CACHE)

    { rap_string("uwsgi_cache"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_uwsgi_cache,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("uwsgi_cache_key"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_uwsgi_cache_key,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("uwsgi_cache_path"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_2MORE,
      rap_http_file_cache_set_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_uwsgi_main_conf_t, caches),
      &rap_http_uwsgi_module },

    { rap_string("uwsgi_cache_bypass"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_set_predicate_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_bypass),
      NULL },

    { rap_string("uwsgi_no_cache"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_set_predicate_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.no_cache),
      NULL },

    { rap_string("uwsgi_cache_valid"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_file_cache_valid_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_valid),
      NULL },

    { rap_string("uwsgi_cache_min_uses"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { rap_string("uwsgi_cache_max_range_offset"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_off_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { rap_string("uwsgi_cache_use_stale"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_use_stale),
      &rap_http_uwsgi_next_upstream_masks },

    { rap_string("uwsgi_cache_methods"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_methods),
      &rap_http_upstream_cache_method_mask },

    { rap_string("uwsgi_cache_lock"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_lock),
      NULL },

    { rap_string("uwsgi_cache_lock_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { rap_string("uwsgi_cache_lock_age"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { rap_string("uwsgi_cache_revalidate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { rap_string("uwsgi_cache_background_update"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { rap_string("uwsgi_temp_path"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1234,
      rap_conf_set_path_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.temp_path),
      NULL },

    { rap_string("uwsgi_max_temp_file_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { rap_string("uwsgi_temp_file_write_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { rap_string("uwsgi_next_upstream"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.next_upstream),
      &rap_http_uwsgi_next_upstream_masks },

    { rap_string("uwsgi_next_upstream_tries"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { rap_string("uwsgi_next_upstream_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { rap_string("uwsgi_param"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE23,
      rap_http_upstream_param_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, params_source),
      NULL },

    { rap_string("uwsgi_string"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, uwsgi_string),
      NULL },

    { rap_string("uwsgi_pass_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.pass_headers),
      NULL },

    { rap_string("uwsgi_hide_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.hide_headers),
      NULL },

    { rap_string("uwsgi_ignore_headers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.ignore_headers),
      &rap_http_upstream_ignore_headers_masks },

#if (RAP_HTTP_SSL)

    { rap_string("uwsgi_ssl_session_reuse"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { rap_string("uwsgi_ssl_protocols"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, ssl_protocols),
      &rap_http_uwsgi_ssl_protocols },

    { rap_string("uwsgi_ssl_ciphers"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, ssl_ciphers),
      NULL },

    { rap_string("uwsgi_ssl_name"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_set_complex_value_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.ssl_name),
      NULL },

    { rap_string("uwsgi_ssl_server_name"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { rap_string("uwsgi_ssl_verify"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, upstream.ssl_verify),
      NULL },

    { rap_string("uwsgi_ssl_verify_depth"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, ssl_verify_depth),
      NULL },

    { rap_string("uwsgi_ssl_trusted_certificate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { rap_string("uwsgi_ssl_crl"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, ssl_crl),
      NULL },

    { rap_string("uwsgi_ssl_certificate"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, ssl_certificate),
      NULL },

    { rap_string("uwsgi_ssl_certificate_key"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_uwsgi_loc_conf_t, ssl_certificate_key),
      NULL },

    { rap_string("uwsgi_ssl_password_file"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_uwsgi_ssl_password_file,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

      rap_null_command
};


static rap_http_module_t rap_http_uwsgi_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_http_uwsgi_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_uwsgi_create_loc_conf,        /* create location configuration */
    rap_http_uwsgi_merge_loc_conf          /* merge location configuration */
};


rap_module_t rap_http_uwsgi_module = {
    RAP_MODULE_V1,
    &rap_http_uwsgi_module_ctx,            /* module context */
    rap_http_uwsgi_commands,               /* module directives */
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


static rap_str_t rap_http_uwsgi_hide_headers[] = {
    rap_string("X-Accel-Expires"),
    rap_string("X-Accel-Redirect"),
    rap_string("X-Accel-Limit-Rate"),
    rap_string("X-Accel-Buffering"),
    rap_string("X-Accel-Charset"),
    rap_null_string
};


#if (RAP_HTTP_CACHE)

static rap_keyval_t  rap_http_uwsgi_cache_headers[] = {
    { rap_string("HTTP_IF_MODIFIED_SINCE"),
      rap_string("$upstream_cache_last_modified") },
    { rap_string("HTTP_IF_UNMODIFIED_SINCE"), rap_string("") },
    { rap_string("HTTP_IF_NONE_MATCH"), rap_string("$upstream_cache_etag") },
    { rap_string("HTTP_IF_MATCH"), rap_string("") },
    { rap_string("HTTP_RANGE"), rap_string("") },
    { rap_string("HTTP_IF_RANGE"), rap_string("") },
    { rap_null_string, rap_null_string }
};

#endif


static rap_path_init_t rap_http_uwsgi_temp_path = {
    rap_string(RAP_HTTP_UWSGI_TEMP_PATH), { 1, 2, 0 }
};


static rap_int_t
rap_http_uwsgi_handler(rap_http_request_t *r)
{
    rap_int_t                    rc;
    rap_http_status_t           *status;
    rap_http_upstream_t         *u;
    rap_http_uwsgi_loc_conf_t   *uwcf;
#if (RAP_HTTP_CACHE)
    rap_http_uwsgi_main_conf_t  *uwmcf;
#endif

    if (rap_http_upstream_create(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    status = rap_pcalloc(r->pool, sizeof(rap_http_status_t));
    if (status == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rap_http_set_ctx(r, status, rap_http_uwsgi_module);

    uwcf = rap_http_get_module_loc_conf(r, rap_http_uwsgi_module);

    u = r->upstream;

    if (uwcf->uwsgi_lengths == NULL) {

#if (RAP_HTTP_SSL)
        u->ssl = (uwcf->upstream.ssl != NULL);

        if (u->ssl) {
            rap_str_set(&u->schema, "suwsgi://");

        } else {
            rap_str_set(&u->schema, "uwsgi://");
        }
#else
        rap_str_set(&u->schema, "uwsgi://");
#endif

    } else {
        if (rap_http_uwsgi_eval(r, uwcf) != RAP_OK) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (rap_buf_tag_t) &rap_http_uwsgi_module;

    u->conf = &uwcf->upstream;

#if (RAP_HTTP_CACHE)
    uwmcf = rap_http_get_module_main_conf(r, rap_http_uwsgi_module);

    u->caches = &uwmcf->caches;
    u->create_key = rap_http_uwsgi_create_key;
#endif

    u->create_request = rap_http_uwsgi_create_request;
    u->reinit_request = rap_http_uwsgi_reinit_request;
    u->process_header = rap_http_uwsgi_process_status_line;
    u->abort_request = rap_http_uwsgi_abort_request;
    u->finalize_request = rap_http_uwsgi_finalize_request;
    r->state = 0;

    u->buffering = uwcf->upstream.buffering;

    u->pipe = rap_pcalloc(r->pool, sizeof(rap_event_pipe_t));
    if (u->pipe == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = rap_event_pipe_copy_input_filter;
    u->pipe->input_ctx = r;

    if (!uwcf->upstream.request_buffering
        && uwcf->upstream.pass_request_body
        && !r->headers_in.chunked)
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
rap_http_uwsgi_eval(rap_http_request_t *r, rap_http_uwsgi_loc_conf_t * uwcf)
{
    size_t                add;
    rap_url_t             url;
    rap_http_upstream_t  *u;

    rap_memzero(&url, sizeof(rap_url_t));

    if (rap_http_script_run(r, &url.url, uwcf->uwsgi_lengths->elts, 0,
                            uwcf->uwsgi_values->elts)
        == NULL)
    {
        return RAP_ERROR;
    }

    if (url.url.len > 8
        && rap_strncasecmp(url.url.data, (u_char *) "uwsgi://", 8) == 0)
    {
        add = 8;

    } else if (url.url.len > 9
               && rap_strncasecmp(url.url.data, (u_char *) "suwsgi://", 9) == 0)
    {

#if (RAP_HTTP_SSL)
        add = 9;
        r->upstream->ssl = 1;
#else
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "suwsgi protocol requires SSL support");
        return RAP_ERROR;
#endif

    } else {
        add = 0;
    }

    u = r->upstream;

    if (add) {
        u->schema.len = add;
        u->schema.data = url.url.data;

        url.url.data += add;
        url.url.len -= add;

    } else {
        rap_str_set(&u->schema, "uwsgi://");
    }

    url.no_resolve = 1;

    if (rap_parse_url(r->pool, &url) != RAP_OK) {
        if (url.err) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return RAP_ERROR;
    }

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
    u->resolved->port = url.port;
    u->resolved->no_port = url.no_port;

    return RAP_OK;
}


#if (RAP_HTTP_CACHE)

static rap_int_t
rap_http_uwsgi_create_key(rap_http_request_t *r)
{
    rap_str_t                  *key;
    rap_http_uwsgi_loc_conf_t  *uwcf;

    key = rap_array_push(&r->cache->keys);
    if (key == NULL) {
        return RAP_ERROR;
    }

    uwcf = rap_http_get_module_loc_conf(r, rap_http_uwsgi_module);

    if (rap_http_complex_value(r, &uwcf->cache_key, key) != RAP_OK) {
        return RAP_ERROR;
    }

    return RAP_OK;
}

#endif


static rap_int_t
rap_http_uwsgi_create_request(rap_http_request_t *r)
{
    u_char                        ch, *lowcase_key;
    size_t                        key_len, val_len, len, allocated;
    rap_uint_t                    i, n, hash, skip_empty, header_params;
    rap_buf_t                    *b;
    rap_chain_t                  *cl, *body;
    rap_list_part_t              *part;
    rap_table_elt_t              *header, **ignored;
    rap_http_uwsgi_params_t      *params;
    rap_http_script_code_pt       code;
    rap_http_script_engine_t      e, le;
    rap_http_uwsgi_loc_conf_t    *uwcf;
    rap_http_script_len_code_pt   lcode;

    len = 0;
    header_params = 0;
    ignored = NULL;

    uwcf = rap_http_get_module_loc_conf(r, rap_http_uwsgi_module);

#if (RAP_HTTP_CACHE)
    params = r->upstream->cacheable ? &uwcf->params_cache : &uwcf->params;
#else
    params = &uwcf->params;
#endif

    if (params->lengths) {
        rap_memzero(&le, sizeof(rap_http_script_engine_t));

        rap_http_script_flush_no_cacheable_variables(r, params->flushes);
        le.flushed = 1;

        le.ip = params->lengths->elts;
        le.request = r;

        while (*(uintptr_t *) le.ip) {

            lcode = *(rap_http_script_len_code_pt *) le.ip;
            key_len = lcode(&le);

            lcode = *(rap_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(rap_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            if (skip_empty && val_len == 0) {
                continue;
            }

            len += 2 + key_len + 2 + val_len;
        }
    }

    if (uwcf->upstream.pass_request_headers) {

        allocated = 0;
        lowcase_key = NULL;

        if (params->number) {
            n = 0;
            part = &r->headers_in.headers.part;

            while (part) {
                n += part->nelts;
                part = part->next;
            }

            ignored = rap_palloc(r->pool, n * sizeof(void *));
            if (ignored == NULL) {
                return RAP_ERROR;
            }
        }

        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (params->number) {
                if (allocated < header[i].key.len) {
                    allocated = header[i].key.len + 16;
                    lowcase_key = rap_pnalloc(r->pool, allocated);
                    if (lowcase_key == NULL) {
                        return RAP_ERROR;
                    }
                }

                hash = 0;

                for (n = 0; n < header[i].key.len; n++) {
                    ch = header[i].key.data[n];

                    if (ch >= 'A' && ch <= 'Z') {
                        ch |= 0x20;

                    } else if (ch == '-') {
                        ch = '_';
                    }

                    hash = rap_hash(hash, ch);
                    lowcase_key[n] = ch;
                }

                if (rap_hash_find(&params->hash, hash, lowcase_key, n)) {
                    ignored[header_params++] = &header[i];
                    continue;
                }
            }

            len += 2 + sizeof("HTTP_") - 1 + header[i].key.len
                 + 2 + header[i].value.len;
        }
    }

    len += uwcf->uwsgi_string.len;

#if 0
    /* allow custom uwsgi packet */
    if (len > 0 && len < 2) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "uwsgi request is too little: %uz", len);
        return RAP_ERROR;
    }
#endif

    if (len > 65535) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "uwsgi request is too big: %uz", len);
        return RAP_ERROR;
    }

    b = rap_create_temp_buf(r->pool, len + 4);
    if (b == NULL) {
        return RAP_ERROR;
    }

    cl = rap_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    cl->buf = b;

    *b->last++ = (u_char) uwcf->modifier1;
    *b->last++ = (u_char) (len & 0xff);
    *b->last++ = (u_char) ((len >> 8) & 0xff);
    *b->last++ = (u_char) uwcf->modifier2;

    if (params->lengths) {
        rap_memzero(&e, sizeof(rap_http_script_engine_t));

        e.ip = params->values->elts;
        e.pos = b->last;
        e.request = r;
        e.flushed = 1;

        le.ip = params->lengths->elts;

        while (*(uintptr_t *) le.ip) {

            lcode = *(rap_http_script_len_code_pt *) le.ip;
            key_len = (u_char) lcode(&le);

            lcode = *(rap_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(rap_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            if (skip_empty && val_len == 0) {
                e.skip = 1;

                while (*(uintptr_t *) e.ip) {
                    code = *(rap_http_script_code_pt *) e.ip;
                    code((rap_http_script_engine_t *) &e);
                }
                e.ip += sizeof(uintptr_t);

                e.skip = 0;

                continue;
            }

            *e.pos++ = (u_char) (key_len & 0xff);
            *e.pos++ = (u_char) ((key_len >> 8) & 0xff);

            code = *(rap_http_script_code_pt *) e.ip;
            code((rap_http_script_engine_t *) &e);

            *e.pos++ = (u_char) (val_len & 0xff);
            *e.pos++ = (u_char) ((val_len >> 8) & 0xff);

            while (*(uintptr_t *) e.ip) {
                code = *(rap_http_script_code_pt *) e.ip;
                code((rap_http_script_engine_t *) &e);
            }

            e.ip += sizeof(uintptr_t);

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "uwsgi param: \"%*s: %*s\"",
                           key_len, e.pos - (key_len + 2 + val_len),
                           val_len, e.pos - val_len);
        }

        b->last = e.pos;
    }

    if (uwcf->upstream.pass_request_headers) {

        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            for (n = 0; n < header_params; n++) {
                if (&header[i] == ignored[n]) {
                    goto next;
                }
            }

            key_len = sizeof("HTTP_") - 1 + header[i].key.len;
            *b->last++ = (u_char) (key_len & 0xff);
            *b->last++ = (u_char) ((key_len >> 8) & 0xff);

            b->last = rap_cpymem(b->last, "HTTP_", sizeof("HTTP_") - 1);
            for (n = 0; n < header[i].key.len; n++) {
                ch = header[i].key.data[n];

                if (ch >= 'a' && ch <= 'z') {
                    ch &= ~0x20;

                } else if (ch == '-') {
                    ch = '_';
                }

                *b->last++ = ch;
            }

            val_len = header[i].value.len;
            *b->last++ = (u_char) (val_len & 0xff);
            *b->last++ = (u_char) ((val_len >> 8) & 0xff);
            b->last = rap_copy(b->last, header[i].value.data, val_len);

            rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "uwsgi param: \"%*s: %*s\"",
                           key_len, b->last - (key_len + 2 + val_len),
                           val_len, b->last - val_len);
        next:

            continue;
        }
    }

    b->last = rap_copy(b->last, uwcf->uwsgi_string.data,
                       uwcf->uwsgi_string.len);

    if (r->request_body_no_buffering) {
        r->upstream->request_bufs = cl;

    } else if (uwcf->upstream.pass_request_body) {
        body = r->upstream->request_bufs;
        r->upstream->request_bufs = cl;

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
        r->upstream->request_bufs = cl;
    }

    cl->next = NULL;

    return RAP_OK;
}


static rap_int_t
rap_http_uwsgi_reinit_request(rap_http_request_t *r)
{
    rap_http_status_t  *status;

    status = rap_http_get_module_ctx(r, rap_http_uwsgi_module);

    if (status == NULL) {
        return RAP_OK;
    }

    status->code = 0;
    status->count = 0;
    status->start = NULL;
    status->end = NULL;

    r->upstream->process_header = rap_http_uwsgi_process_status_line;
    r->state = 0;

    return RAP_OK;
}


static rap_int_t
rap_http_uwsgi_process_status_line(rap_http_request_t *r)
{
    size_t                 len;
    rap_int_t              rc;
    rap_http_status_t     *status;
    rap_http_upstream_t   *u;

    status = rap_http_get_module_ctx(r, rap_http_uwsgi_module);

    if (status == NULL) {
        return RAP_ERROR;
    }

    u = r->upstream;

    rc = rap_http_parse_status_line(r, &u->buffer, status);

    if (rc == RAP_AGAIN) {
        return rc;
    }

    if (rc == RAP_ERROR) {
        u->process_header = rap_http_uwsgi_process_header;
        return rap_http_uwsgi_process_header(r);
    }

    if (u->state && u->state->status == 0) {
        u->state->status = status->code;
    }

    u->headers_in.status_n = status->code;

    len = status->end - status->start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = rap_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(u->headers_in.status_line.data, status->start, len);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uwsgi status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    u->process_header = rap_http_uwsgi_process_header;

    return rap_http_uwsgi_process_header(r);
}


static rap_int_t
rap_http_uwsgi_process_header(rap_http_request_t *r)
{
    rap_str_t                      *status_line;
    rap_int_t                       rc, status;
    rap_table_elt_t                *h;
    rap_http_upstream_t            *u;
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
                                      h->key.len + 1 + h->value.len + 1
                                      + h->key.len);
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
                           "http uwsgi header: \"%V: %V\"", &h->key, &h->value);

            continue;
        }

        if (rc == RAP_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http uwsgi header done");

            u = r->upstream;

            if (u->headers_in.status_n) {
                goto done;
            }

            if (u->headers_in.status) {
                status_line = &u->headers_in.status->value;

                status = rap_atoi(status_line->data, 3);
                if (status == RAP_ERROR) {
                    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid status \"%V\"",
                                  status_line);
                    return RAP_HTTP_UPSTREAM_INVALID_HEADER;
                }

                u->headers_in.status_n = status;
                u->headers_in.status_line = *status_line;

            } else if (u->headers_in.location) {
                u->headers_in.status_n = 302;
                rap_str_set(&u->headers_in.status_line,
                            "302 Moved Temporarily");

            } else {
                u->headers_in.status_n = 200;
                rap_str_set(&u->headers_in.status_line, "200 OK");
            }

            if (u->state && u->state->status == 0) {
                u->state->status = u->headers_in.status_n;
            }

        done:

            if (u->headers_in.status_n == RAP_HTTP_SWITCHING_PROTOCOLS
                && r->headers_in.upgrade)
            {
                u->upgrade = 1;
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


static void
rap_http_uwsgi_abort_request(rap_http_request_t *r)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http uwsgi request");

    return;
}


static void
rap_http_uwsgi_finalize_request(rap_http_request_t *r, rap_int_t rc)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http uwsgi request");

    return;
}


static void *
rap_http_uwsgi_create_main_conf(rap_conf_t *cf)
{
    rap_http_uwsgi_main_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_uwsgi_main_conf_t));
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
rap_http_uwsgi_create_loc_conf(rap_conf_t *cf)
{
    rap_http_uwsgi_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_uwsgi_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->modifier1 = RAP_CONF_UNSET_UINT;
    conf->modifier2 = RAP_CONF_UNSET_UINT;

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

    /* "uwsgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    rap_str_set(&conf->upstream.module, "uwsgi");

    return conf;
}


static char *
rap_http_uwsgi_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_uwsgi_loc_conf_t *prev = parent;
    rap_http_uwsgi_loc_conf_t *conf = child;

    size_t                        size;
    rap_int_t                     rc;
    rap_hash_init_t               hash;
    rap_http_core_loc_conf_t     *clcf;

#if (RAP_HTTP_CACHE)

    if (conf->upstream.store > 0) {
        conf->upstream.cache = 0;
    }

    if (conf->upstream.cache > 0) {
        conf->upstream.store = 0;
    }

#endif

    if (conf->upstream.store == RAP_CONF_UNSET) {
        rap_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);

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
                           "there must be at least 2 \"uwsgi_buffers\"");
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
            "\"uwsgi_busy_buffers_size\" must be equal to or greater "
            "than the maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

        return RAP_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
            "\"uwsgi_busy_buffers_size\" must be less than "
            "the size of all \"uwsgi_buffers\" minus one buffer");

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
            "\"uwsgi_temp_file_write_size\" must be equal to or greater than "
            "the maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

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
            "\"uwsgi_max_temp_file_size\" must be equal to zero to disable "
            "temporary files usage or must be equal to or greater than "
            "the maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

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
                                  &rap_http_uwsgi_temp_path)
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
                           "\"uwsgi_cache\" zone \"%V\" is unknown",
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

    if (conf->upstream.cache && conf->cache_key.value.data == NULL) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "no \"uwsgi_cache_key\" for \"uwsgi_cache\"");
    }

    rap_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    rap_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

    rap_conf_merge_msec_value(conf->upstream.cache_lock_age,
                              prev->upstream.cache_lock_age, 5000);

    rap_conf_merge_value(conf->upstream.cache_revalidate,
                              prev->upstream.cache_revalidate, 0);

    rap_conf_merge_value(conf->upstream.cache_background_update,
                              prev->upstream.cache_background_update, 0);

#endif

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

    if (conf->ssl && rap_http_uwsgi_set_ssl(cf, conf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

#endif

    rap_conf_merge_str_value(conf->uwsgi_string, prev->uwsgi_string, "");

    hash.max_size = 512;
    hash.bucket_size = rap_align(64, rap_cacheline_size);
    hash.name = "uwsgi_hide_headers_hash";

    if (rap_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, rap_http_uwsgi_hide_headers, &hash)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->uwsgi_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;

        conf->uwsgi_lengths = prev->uwsgi_lengths;
        conf->uwsgi_values = prev->uwsgi_values;

#if (RAP_HTTP_SSL)
        conf->upstream.ssl = prev->upstream.ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->uwsgi_lengths))
    {
        clcf->handler = rap_http_uwsgi_handler;
    }

    rap_conf_merge_uint_value(conf->modifier1, prev->modifier1, 0);
    rap_conf_merge_uint_value(conf->modifier2, prev->modifier2, 0);

    if (conf->params_source == NULL) {
        conf->params = prev->params;
#if (RAP_HTTP_CACHE)
        conf->params_cache = prev->params_cache;
#endif
        conf->params_source = prev->params_source;
    }

    rc = rap_http_uwsgi_init_params(cf, conf, &conf->params, NULL);
    if (rc != RAP_OK) {
        return RAP_CONF_ERROR;
    }

#if (RAP_HTTP_CACHE)

    if (conf->upstream.cache) {
        rc = rap_http_uwsgi_init_params(cf, conf, &conf->params_cache,
                                        rap_http_uwsgi_cache_headers);
        if (rc != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

#endif

    /*
     * special handling to preserve conf->params in the "http" section
     * to inherit it to all servers
     */

    if (prev->params.hash.buckets == NULL
        && conf->params_source == prev->params_source)
    {
        prev->params = conf->params;
#if (RAP_HTTP_CACHE)
        prev->params_cache = conf->params_cache;
#endif
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_uwsgi_init_params(rap_conf_t *cf, rap_http_uwsgi_loc_conf_t *conf,
    rap_http_uwsgi_params_t *params, rap_keyval_t *default_params)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    rap_uint_t                    i, nsrc;
    rap_array_t                   headers_names, params_merged;
    rap_keyval_t                 *h;
    rap_hash_key_t               *hk;
    rap_hash_init_t               hash;
    rap_http_upstream_param_t    *src, *s;
    rap_http_script_compile_t     sc;
    rap_http_script_copy_code_t  *copy;

    if (params->hash.buckets) {
        return RAP_OK;
    }

    if (conf->params_source == NULL && default_params == NULL) {
        params->hash.buckets = (void *) 1;
        return RAP_OK;
    }

    params->lengths = rap_array_create(cf->pool, 64, 1);
    if (params->lengths == NULL) {
        return RAP_ERROR;
    }

    params->values = rap_array_create(cf->pool, 512, 1);
    if (params->values == NULL) {
        return RAP_ERROR;
    }

    if (rap_array_init(&headers_names, cf->temp_pool, 4, sizeof(rap_hash_key_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (conf->params_source) {
        src = conf->params_source->elts;
        nsrc = conf->params_source->nelts;

    } else {
        src = NULL;
        nsrc = 0;
    }

    if (default_params) {
        if (rap_array_init(&params_merged, cf->temp_pool, 4,
                           sizeof(rap_http_upstream_param_t))
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        for (i = 0; i < nsrc; i++) {

            s = rap_array_push(&params_merged);
            if (s == NULL) {
                return RAP_ERROR;
            }

            *s = src[i];
        }

        h = default_params;

        while (h->key.len) {

            src = params_merged.elts;
            nsrc = params_merged.nelts;

            for (i = 0; i < nsrc; i++) {
                if (rap_strcasecmp(h->key.data, src[i].key.data) == 0) {
                    goto next;
                }
            }

            s = rap_array_push(&params_merged);
            if (s == NULL) {
                return RAP_ERROR;
            }

            s->key = h->key;
            s->value = h->value;
            s->skip_empty = 1;

        next:

            h++;
        }

        src = params_merged.elts;
        nsrc = params_merged.nelts;
    }

    for (i = 0; i < nsrc; i++) {

        if (src[i].key.len > sizeof("HTTP_") - 1
            && rap_strncmp(src[i].key.data, "HTTP_", sizeof("HTTP_") - 1) == 0)
        {
            hk = rap_array_push(&headers_names);
            if (hk == NULL) {
                return RAP_ERROR;
            }

            hk->key.len = src[i].key.len - 5;
            hk->key.data = src[i].key.data + 5;
            hk->key_hash = rap_hash_key_lc(hk->key.data, hk->key.len);
            hk->value = (void *) 1;

            if (src[i].value.len == 0) {
                continue;
            }
        }

        copy = rap_array_push_n(params->lengths,
                                sizeof(rap_http_script_copy_code_t));
        if (copy == NULL) {
            return RAP_ERROR;
        }

        copy->code = (rap_http_script_code_pt) (void *)
                                                 rap_http_script_copy_len_code;
        copy->len = src[i].key.len;

        copy = rap_array_push_n(params->lengths,
                                sizeof(rap_http_script_copy_code_t));
        if (copy == NULL) {
            return RAP_ERROR;
        }

        copy->code = (rap_http_script_code_pt) (void *)
                                                 rap_http_script_copy_len_code;
        copy->len = src[i].skip_empty;


        size = (sizeof(rap_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = rap_array_push_n(params->values, size);
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
        sc.flushes = &params->flushes;
        sc.lengths = &params->lengths;
        sc.values = &params->values;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_ERROR;
        }

        code = rap_array_push_n(params->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;


        code = rap_array_push_n(params->values, sizeof(uintptr_t));
        if (code == NULL) {
            return RAP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = rap_array_push_n(params->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return RAP_ERROR;
    }

    *code = (uintptr_t) NULL;

    params->number = headers_names.nelts;

    hash.hash = &params->hash;
    hash.key = rap_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "uwsgi_params_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return rap_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
rap_http_uwsgi_pass(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_uwsgi_loc_conf_t *uwcf = conf;

    size_t                      add;
    rap_url_t                   u;
    rap_str_t                  *value, *url;
    rap_uint_t                  n;
    rap_http_core_loc_conf_t   *clcf;
    rap_http_script_compile_t   sc;

    if (uwcf->upstream.upstream || uwcf->uwsgi_lengths) {
        return "is duplicate";
    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);
    clcf->handler = rap_http_uwsgi_handler;

    value = cf->args->elts;

    url = &value[1];

    n = rap_http_script_variables_count(url);

    if (n) {

        rap_memzero(&sc, sizeof(rap_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &uwcf->uwsgi_lengths;
        sc.values = &uwcf->uwsgi_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rap_http_script_compile(&sc) != RAP_OK) {
            return RAP_CONF_ERROR;
        }

#if (RAP_HTTP_SSL)
        uwcf->ssl = 1;
#endif

        return RAP_CONF_OK;
    }

    if (rap_strncasecmp(url->data, (u_char *) "uwsgi://", 8) == 0) {
        add = 8;

    } else if (rap_strncasecmp(url->data, (u_char *) "suwsgi://", 9) == 0) {

#if (RAP_HTTP_SSL)
        add = 9;
        uwcf->ssl = 1;
#else
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "suwsgi protocol requires SSL support");
        return RAP_CONF_ERROR;
#endif

    } else {
        add = 0;
    }

    rap_memzero(&u, sizeof(rap_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.no_resolve = 1;

    uwcf->upstream.upstream = rap_http_upstream_add(cf, &u, 0);
    if (uwcf->upstream.upstream == NULL) {
        return RAP_CONF_ERROR;
    }

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_uwsgi_store(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_uwsgi_loc_conf_t *uwcf = conf;

    rap_str_t                  *value;
    rap_http_script_compile_t   sc;

    if (uwcf->upstream.store != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {
        uwcf->upstream.store = 0;
        return RAP_CONF_OK;
    }

#if (RAP_HTTP_CACHE)

    if (uwcf->upstream.cache > 0) {
        return "is incompatible with \"uwsgi_cache\"";
    }

#endif

    uwcf->upstream.store = 1;

    if (rap_strcmp(value[1].data, "on") == 0) {
        return RAP_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    rap_memzero(&sc, sizeof(rap_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &uwcf->upstream.store_lengths;
    sc.values = &uwcf->upstream.store_values;
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
rap_http_uwsgi_cache(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_uwsgi_loc_conf_t *uwcf = conf;

    rap_str_t                         *value;
    rap_http_complex_value_t           cv;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (uwcf->upstream.cache != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    if (rap_strcmp(value[1].data, "off") == 0) {
        uwcf->upstream.cache = 0;
        return RAP_CONF_OK;
    }

    if (uwcf->upstream.store > 0) {
        return "is incompatible with \"uwsgi_store\"";
    }

    uwcf->upstream.cache = 1;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        uwcf->upstream.cache_value = rap_palloc(cf->pool,
                                             sizeof(rap_http_complex_value_t));
        if (uwcf->upstream.cache_value == NULL) {
            return RAP_CONF_ERROR;
        }

        *uwcf->upstream.cache_value = cv;

        return RAP_CONF_OK;
    }

    uwcf->upstream.cache_zone = rap_shared_memory_add(cf, &value[1], 0,
                                                      &rap_http_uwsgi_module);
    if (uwcf->upstream.cache_zone == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_uwsgi_cache_key(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_uwsgi_loc_conf_t *uwcf = conf;

    rap_str_t                         *value;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (uwcf->cache_key.value.data) {
        return "is duplicate";
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &uwcf->cache_key;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}

#endif


#if (RAP_HTTP_SSL)

static char *
rap_http_uwsgi_ssl_password_file(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_uwsgi_loc_conf_t *uwcf = conf;

    rap_str_t  *value;

    if (uwcf->ssl_passwords != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    uwcf->ssl_passwords = rap_ssl_read_password_file(cf, &value[1]);

    if (uwcf->ssl_passwords == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_uwsgi_set_ssl(rap_conf_t *cf, rap_http_uwsgi_loc_conf_t *uwcf)
{
    rap_pool_cleanup_t  *cln;

    uwcf->upstream.ssl = rap_pcalloc(cf->pool, sizeof(rap_ssl_t));
    if (uwcf->upstream.ssl == NULL) {
        return RAP_ERROR;
    }

    uwcf->upstream.ssl->log = cf->log;

    if (rap_ssl_create(uwcf->upstream.ssl, uwcf->ssl_protocols, NULL)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rap_ssl_cleanup_ctx(uwcf->upstream.ssl);
        return RAP_ERROR;
    }

    cln->handler = rap_ssl_cleanup_ctx;
    cln->data = uwcf->upstream.ssl;

    if (uwcf->ssl_certificate.len) {

        if (uwcf->ssl_certificate_key.len == 0) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "no \"uwsgi_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &uwcf->ssl_certificate);
            return RAP_ERROR;
        }

        if (rap_ssl_certificate(cf, uwcf->upstream.ssl, &uwcf->ssl_certificate,
                                &uwcf->ssl_certificate_key, uwcf->ssl_passwords)
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    if (rap_ssl_ciphers(cf, uwcf->upstream.ssl, &uwcf->ssl_ciphers, 0)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (uwcf->upstream.ssl_verify) {
        if (uwcf->ssl_trusted_certificate.len == 0) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no uwsgi_ssl_trusted_certificate for uwsgi_ssl_verify");
            return RAP_ERROR;
        }

        if (rap_ssl_trusted_certificate(cf, uwcf->upstream.ssl,
                                        &uwcf->ssl_trusted_certificate,
                                        uwcf->ssl_verify_depth)
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        if (rap_ssl_crl(cf, uwcf->upstream.ssl, &uwcf->ssl_crl) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    if (rap_ssl_client_session_cache(cf, uwcf->upstream.ssl,
                                     uwcf->upstream.ssl_session_reuse)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    return RAP_OK;
}

#endif
