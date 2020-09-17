
/*
 * Copyright (C) Unbit S.a.s. 2009-2010
 * Copyright (C) 2008 Manlio Perillo (manlio.perillo@gmail.com)
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_array_t                caches;  /* rp_http_file_cache_t * */
} rp_http_uwsgi_main_conf_t;


typedef struct {
    rp_array_t               *flushes;
    rp_array_t               *lengths;
    rp_array_t               *values;
    rp_uint_t                 number;
    rp_hash_t                 hash;
} rp_http_uwsgi_params_t;


typedef struct {
    rp_http_upstream_conf_t   upstream;

    rp_http_uwsgi_params_t    params;
#if (RP_HTTP_CACHE)
    rp_http_uwsgi_params_t    params_cache;
#endif
    rp_array_t               *params_source;

    rp_array_t               *uwsgi_lengths;
    rp_array_t               *uwsgi_values;

#if (RP_HTTP_CACHE)
    rp_http_complex_value_t   cache_key;
#endif

    rp_str_t                  uwsgi_string;

    rp_uint_t                 modifier1;
    rp_uint_t                 modifier2;

#if (RP_HTTP_SSL)
    rp_uint_t                 ssl;
    rp_uint_t                 ssl_protocols;
    rp_str_t                  ssl_ciphers;
    rp_uint_t                 ssl_verify_depth;
    rp_str_t                  ssl_trusted_certificate;
    rp_str_t                  ssl_crl;
    rp_str_t                  ssl_certificate;
    rp_str_t                  ssl_certificate_key;
    rp_array_t               *ssl_passwords;
#endif
} rp_http_uwsgi_loc_conf_t;


static rp_int_t rp_http_uwsgi_eval(rp_http_request_t *r,
    rp_http_uwsgi_loc_conf_t *uwcf);
static rp_int_t rp_http_uwsgi_create_request(rp_http_request_t *r);
static rp_int_t rp_http_uwsgi_reinit_request(rp_http_request_t *r);
static rp_int_t rp_http_uwsgi_process_status_line(rp_http_request_t *r);
static rp_int_t rp_http_uwsgi_process_header(rp_http_request_t *r);
static void rp_http_uwsgi_abort_request(rp_http_request_t *r);
static void rp_http_uwsgi_finalize_request(rp_http_request_t *r,
    rp_int_t rc);

static void *rp_http_uwsgi_create_main_conf(rp_conf_t *cf);
static void *rp_http_uwsgi_create_loc_conf(rp_conf_t *cf);
static char *rp_http_uwsgi_merge_loc_conf(rp_conf_t *cf, void *parent,
    void *child);
static rp_int_t rp_http_uwsgi_init_params(rp_conf_t *cf,
    rp_http_uwsgi_loc_conf_t *conf, rp_http_uwsgi_params_t *params,
    rp_keyval_t *default_params);

static char *rp_http_uwsgi_pass(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_uwsgi_store(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);

#if (RP_HTTP_CACHE)
static rp_int_t rp_http_uwsgi_create_key(rp_http_request_t *r);
static char *rp_http_uwsgi_cache(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_uwsgi_cache_key(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
#endif

#if (RP_HTTP_SSL)
static char *rp_http_uwsgi_ssl_password_file(rp_conf_t *cf,
    rp_command_t *cmd, void *conf);
static rp_int_t rp_http_uwsgi_set_ssl(rp_conf_t *cf,
    rp_http_uwsgi_loc_conf_t *uwcf);
#endif


static rp_conf_num_bounds_t  rp_http_uwsgi_modifier_bounds = {
    rp_conf_check_num_bounds, 0, 255
};


static rp_conf_bitmask_t rp_http_uwsgi_next_upstream_masks[] = {
    { rp_string("error"), RP_HTTP_UPSTREAM_FT_ERROR },
    { rp_string("timeout"), RP_HTTP_UPSTREAM_FT_TIMEOUT },
    { rp_string("invalid_header"), RP_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { rp_string("non_idempotent"), RP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT },
    { rp_string("http_500"), RP_HTTP_UPSTREAM_FT_HTTP_500 },
    { rp_string("http_503"), RP_HTTP_UPSTREAM_FT_HTTP_503 },
    { rp_string("http_403"), RP_HTTP_UPSTREAM_FT_HTTP_403 },
    { rp_string("http_404"), RP_HTTP_UPSTREAM_FT_HTTP_404 },
    { rp_string("http_429"), RP_HTTP_UPSTREAM_FT_HTTP_429 },
    { rp_string("updating"), RP_HTTP_UPSTREAM_FT_UPDATING },
    { rp_string("off"), RP_HTTP_UPSTREAM_FT_OFF },
    { rp_null_string, 0 }
};


#if (RP_HTTP_SSL)

static rp_conf_bitmask_t  rp_http_uwsgi_ssl_protocols[] = {
    { rp_string("SSLv2"), RP_SSL_SSLv2 },
    { rp_string("SSLv3"), RP_SSL_SSLv3 },
    { rp_string("TLSv1"), RP_SSL_TLSv1 },
    { rp_string("TLSv1.1"), RP_SSL_TLSv1_1 },
    { rp_string("TLSv1.2"), RP_SSL_TLSv1_2 },
    { rp_string("TLSv1.3"), RP_SSL_TLSv1_3 },
    { rp_null_string, 0 }
};

#endif


rp_module_t  rp_http_uwsgi_module;


static rp_command_t rp_http_uwsgi_commands[] = {

    { rp_string("uwsgi_pass"),
      RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF|RP_CONF_TAKE1,
      rp_http_uwsgi_pass,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("uwsgi_modifier1"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, modifier1),
      &rp_http_uwsgi_modifier_bounds },

    { rp_string("uwsgi_modifier2"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, modifier2),
      &rp_http_uwsgi_modifier_bounds },

    { rp_string("uwsgi_store"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_uwsgi_store,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("uwsgi_store_access"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE123,
      rp_conf_set_access_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.store_access),
      NULL },

    { rp_string("uwsgi_buffering"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.buffering),
      NULL },

    { rp_string("uwsgi_request_buffering"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.request_buffering),
      NULL },

    { rp_string("uwsgi_ignore_client_abort"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { rp_string("uwsgi_bind"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE12,
      rp_http_upstream_bind_set_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.local),
      NULL },

    { rp_string("uwsgi_socket_keepalive"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { rp_string("uwsgi_connect_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.connect_timeout),
      NULL },

    { rp_string("uwsgi_send_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.send_timeout),
      NULL },

    { rp_string("uwsgi_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.buffer_size),
      NULL },

    { rp_string("uwsgi_pass_request_headers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { rp_string("uwsgi_pass_request_body"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.pass_request_body),
      NULL },

    { rp_string("uwsgi_intercept_errors"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.intercept_errors),
      NULL },

    { rp_string("uwsgi_read_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.read_timeout),
      NULL },

    { rp_string("uwsgi_buffers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_conf_set_bufs_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.bufs),
      NULL },

    { rp_string("uwsgi_busy_buffers_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { rp_string("uwsgi_force_ranges"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.force_ranges),
      NULL },

    { rp_string("uwsgi_limit_rate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.limit_rate),
      NULL },

#if (RP_HTTP_CACHE)

    { rp_string("uwsgi_cache"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_uwsgi_cache,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("uwsgi_cache_key"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_uwsgi_cache_key,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("uwsgi_cache_path"),
      RP_HTTP_MAIN_CONF|RP_CONF_2MORE,
      rp_http_file_cache_set_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_uwsgi_main_conf_t, caches),
      &rp_http_uwsgi_module },

    { rp_string("uwsgi_cache_bypass"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_set_predicate_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_bypass),
      NULL },

    { rp_string("uwsgi_no_cache"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_set_predicate_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.no_cache),
      NULL },

    { rp_string("uwsgi_cache_valid"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_file_cache_valid_set_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_valid),
      NULL },

    { rp_string("uwsgi_cache_min_uses"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { rp_string("uwsgi_cache_max_range_offset"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_off_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { rp_string("uwsgi_cache_use_stale"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_use_stale),
      &rp_http_uwsgi_next_upstream_masks },

    { rp_string("uwsgi_cache_methods"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_methods),
      &rp_http_upstream_cache_method_mask },

    { rp_string("uwsgi_cache_lock"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_lock),
      NULL },

    { rp_string("uwsgi_cache_lock_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { rp_string("uwsgi_cache_lock_age"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { rp_string("uwsgi_cache_revalidate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { rp_string("uwsgi_cache_background_update"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { rp_string("uwsgi_temp_path"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1234,
      rp_conf_set_path_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.temp_path),
      NULL },

    { rp_string("uwsgi_max_temp_file_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { rp_string("uwsgi_temp_file_write_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { rp_string("uwsgi_next_upstream"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.next_upstream),
      &rp_http_uwsgi_next_upstream_masks },

    { rp_string("uwsgi_next_upstream_tries"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { rp_string("uwsgi_next_upstream_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { rp_string("uwsgi_param"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE23,
      rp_http_upstream_param_set_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, params_source),
      NULL },

    { rp_string("uwsgi_string"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, uwsgi_string),
      NULL },

    { rp_string("uwsgi_pass_header"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.pass_headers),
      NULL },

    { rp_string("uwsgi_hide_header"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.hide_headers),
      NULL },

    { rp_string("uwsgi_ignore_headers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.ignore_headers),
      &rp_http_upstream_ignore_headers_masks },

#if (RP_HTTP_SSL)

    { rp_string("uwsgi_ssl_session_reuse"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.ssl_session_reuse),
      NULL },

    { rp_string("uwsgi_ssl_protocols"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, ssl_protocols),
      &rp_http_uwsgi_ssl_protocols },

    { rp_string("uwsgi_ssl_ciphers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, ssl_ciphers),
      NULL },

    { rp_string("uwsgi_ssl_name"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_set_complex_value_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.ssl_name),
      NULL },

    { rp_string("uwsgi_ssl_server_name"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.ssl_server_name),
      NULL },

    { rp_string("uwsgi_ssl_verify"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, upstream.ssl_verify),
      NULL },

    { rp_string("uwsgi_ssl_verify_depth"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, ssl_verify_depth),
      NULL },

    { rp_string("uwsgi_ssl_trusted_certificate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, ssl_trusted_certificate),
      NULL },

    { rp_string("uwsgi_ssl_crl"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, ssl_crl),
      NULL },

    { rp_string("uwsgi_ssl_certificate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, ssl_certificate),
      NULL },

    { rp_string("uwsgi_ssl_certificate_key"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_uwsgi_loc_conf_t, ssl_certificate_key),
      NULL },

    { rp_string("uwsgi_ssl_password_file"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_uwsgi_ssl_password_file,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

#endif

      rp_null_command
};


static rp_http_module_t rp_http_uwsgi_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rp_http_uwsgi_create_main_conf,       /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_uwsgi_create_loc_conf,        /* create location configuration */
    rp_http_uwsgi_merge_loc_conf          /* merge location configuration */
};


rp_module_t rp_http_uwsgi_module = {
    RP_MODULE_V1,
    &rp_http_uwsgi_module_ctx,            /* module context */
    rp_http_uwsgi_commands,               /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_str_t rp_http_uwsgi_hide_headers[] = {
    rp_string("X-Accel-Expires"),
    rp_string("X-Accel-Redirect"),
    rp_string("X-Accel-Limit-Rate"),
    rp_string("X-Accel-Buffering"),
    rp_string("X-Accel-Charset"),
    rp_null_string
};


#if (RP_HTTP_CACHE)

static rp_keyval_t  rp_http_uwsgi_cache_headers[] = {
    { rp_string("HTTP_IF_MODIFIED_SINCE"),
      rp_string("$upstream_cache_last_modified") },
    { rp_string("HTTP_IF_UNMODIFIED_SINCE"), rp_string("") },
    { rp_string("HTTP_IF_NONE_MATCH"), rp_string("$upstream_cache_etag") },
    { rp_string("HTTP_IF_MATCH"), rp_string("") },
    { rp_string("HTTP_RANGE"), rp_string("") },
    { rp_string("HTTP_IF_RANGE"), rp_string("") },
    { rp_null_string, rp_null_string }
};

#endif


static rp_path_init_t rp_http_uwsgi_temp_path = {
    rp_string(RP_HTTP_UWSGI_TEMP_PATH), { 1, 2, 0 }
};


static rp_int_t
rp_http_uwsgi_handler(rp_http_request_t *r)
{
    rp_int_t                    rc;
    rp_http_status_t           *status;
    rp_http_upstream_t         *u;
    rp_http_uwsgi_loc_conf_t   *uwcf;
#if (RP_HTTP_CACHE)
    rp_http_uwsgi_main_conf_t  *uwmcf;
#endif

    if (rp_http_upstream_create(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    status = rp_pcalloc(r->pool, sizeof(rp_http_status_t));
    if (status == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rp_http_set_ctx(r, status, rp_http_uwsgi_module);

    uwcf = rp_http_get_module_loc_conf(r, rp_http_uwsgi_module);

    u = r->upstream;

    if (uwcf->uwsgi_lengths == NULL) {

#if (RP_HTTP_SSL)
        u->ssl = (uwcf->upstream.ssl != NULL);

        if (u->ssl) {
            rp_str_set(&u->schema, "suwsgi://");

        } else {
            rp_str_set(&u->schema, "uwsgi://");
        }
#else
        rp_str_set(&u->schema, "uwsgi://");
#endif

    } else {
        if (rp_http_uwsgi_eval(r, uwcf) != RP_OK) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u->output.tag = (rp_buf_tag_t) &rp_http_uwsgi_module;

    u->conf = &uwcf->upstream;

#if (RP_HTTP_CACHE)
    uwmcf = rp_http_get_module_main_conf(r, rp_http_uwsgi_module);

    u->caches = &uwmcf->caches;
    u->create_key = rp_http_uwsgi_create_key;
#endif

    u->create_request = rp_http_uwsgi_create_request;
    u->reinit_request = rp_http_uwsgi_reinit_request;
    u->process_header = rp_http_uwsgi_process_status_line;
    u->abort_request = rp_http_uwsgi_abort_request;
    u->finalize_request = rp_http_uwsgi_finalize_request;
    r->state = 0;

    u->buffering = uwcf->upstream.buffering;

    u->pipe = rp_pcalloc(r->pool, sizeof(rp_event_pipe_t));
    if (u->pipe == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = rp_event_pipe_copy_input_filter;
    u->pipe->input_ctx = r;

    if (!uwcf->upstream.request_buffering
        && uwcf->upstream.pass_request_body
        && !r->headers_in.chunked)
    {
        r->request_body_no_buffering = 1;
    }

    rc = rp_http_read_client_request_body(r, rp_http_upstream_init);

    if (rc >= RP_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return RP_DONE;
}


static rp_int_t
rp_http_uwsgi_eval(rp_http_request_t *r, rp_http_uwsgi_loc_conf_t * uwcf)
{
    size_t                add;
    rp_url_t             url;
    rp_http_upstream_t  *u;

    rp_memzero(&url, sizeof(rp_url_t));

    if (rp_http_script_run(r, &url.url, uwcf->uwsgi_lengths->elts, 0,
                            uwcf->uwsgi_values->elts)
        == NULL)
    {
        return RP_ERROR;
    }

    if (url.url.len > 8
        && rp_strncasecmp(url.url.data, (u_char *) "uwsgi://", 8) == 0)
    {
        add = 8;

    } else if (url.url.len > 9
               && rp_strncasecmp(url.url.data, (u_char *) "suwsgi://", 9) == 0)
    {

#if (RP_HTTP_SSL)
        add = 9;
        r->upstream->ssl = 1;
#else
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "suwsgi protocol requires SSL support");
        return RP_ERROR;
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
        rp_str_set(&u->schema, "uwsgi://");
    }

    url.no_resolve = 1;

    if (rp_parse_url(r->pool, &url) != RP_OK) {
        if (url.err) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return RP_ERROR;
    }

    u->resolved = rp_pcalloc(r->pool, sizeof(rp_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return RP_ERROR;
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

    return RP_OK;
}


#if (RP_HTTP_CACHE)

static rp_int_t
rp_http_uwsgi_create_key(rp_http_request_t *r)
{
    rp_str_t                  *key;
    rp_http_uwsgi_loc_conf_t  *uwcf;

    key = rp_array_push(&r->cache->keys);
    if (key == NULL) {
        return RP_ERROR;
    }

    uwcf = rp_http_get_module_loc_conf(r, rp_http_uwsgi_module);

    if (rp_http_complex_value(r, &uwcf->cache_key, key) != RP_OK) {
        return RP_ERROR;
    }

    return RP_OK;
}

#endif


static rp_int_t
rp_http_uwsgi_create_request(rp_http_request_t *r)
{
    u_char                        ch, *lowcase_key;
    size_t                        key_len, val_len, len, allocated;
    rp_uint_t                    i, n, hash, skip_empty, header_params;
    rp_buf_t                    *b;
    rp_chain_t                  *cl, *body;
    rp_list_part_t              *part;
    rp_table_elt_t              *header, **ignored;
    rp_http_uwsgi_params_t      *params;
    rp_http_script_code_pt       code;
    rp_http_script_engine_t      e, le;
    rp_http_uwsgi_loc_conf_t    *uwcf;
    rp_http_script_len_code_pt   lcode;

    len = 0;
    header_params = 0;
    ignored = NULL;

    uwcf = rp_http_get_module_loc_conf(r, rp_http_uwsgi_module);

#if (RP_HTTP_CACHE)
    params = r->upstream->cacheable ? &uwcf->params_cache : &uwcf->params;
#else
    params = &uwcf->params;
#endif

    if (params->lengths) {
        rp_memzero(&le, sizeof(rp_http_script_engine_t));

        rp_http_script_flush_no_cacheable_variables(r, params->flushes);
        le.flushed = 1;

        le.ip = params->lengths->elts;
        le.request = r;

        while (*(uintptr_t *) le.ip) {

            lcode = *(rp_http_script_len_code_pt *) le.ip;
            key_len = lcode(&le);

            lcode = *(rp_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(rp_http_script_len_code_pt *) le.ip;
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

            ignored = rp_palloc(r->pool, n * sizeof(void *));
            if (ignored == NULL) {
                return RP_ERROR;
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
                    lowcase_key = rp_pnalloc(r->pool, allocated);
                    if (lowcase_key == NULL) {
                        return RP_ERROR;
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

                    hash = rp_hash(hash, ch);
                    lowcase_key[n] = ch;
                }

                if (rp_hash_find(&params->hash, hash, lowcase_key, n)) {
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
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "uwsgi request is too little: %uz", len);
        return RP_ERROR;
    }
#endif

    if (len > 65535) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "uwsgi request is too big: %uz", len);
        return RP_ERROR;
    }

    b = rp_create_temp_buf(r->pool, len + 4);
    if (b == NULL) {
        return RP_ERROR;
    }

    cl = rp_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RP_ERROR;
    }

    cl->buf = b;

    *b->last++ = (u_char) uwcf->modifier1;
    *b->last++ = (u_char) (len & 0xff);
    *b->last++ = (u_char) ((len >> 8) & 0xff);
    *b->last++ = (u_char) uwcf->modifier2;

    if (params->lengths) {
        rp_memzero(&e, sizeof(rp_http_script_engine_t));

        e.ip = params->values->elts;
        e.pos = b->last;
        e.request = r;
        e.flushed = 1;

        le.ip = params->lengths->elts;

        while (*(uintptr_t *) le.ip) {

            lcode = *(rp_http_script_len_code_pt *) le.ip;
            key_len = (u_char) lcode(&le);

            lcode = *(rp_http_script_len_code_pt *) le.ip;
            skip_empty = lcode(&le);

            for (val_len = 0; *(uintptr_t *) le.ip; val_len += lcode(&le)) {
                lcode = *(rp_http_script_len_code_pt *) le.ip;
            }
            le.ip += sizeof(uintptr_t);

            if (skip_empty && val_len == 0) {
                e.skip = 1;

                while (*(uintptr_t *) e.ip) {
                    code = *(rp_http_script_code_pt *) e.ip;
                    code((rp_http_script_engine_t *) &e);
                }
                e.ip += sizeof(uintptr_t);

                e.skip = 0;

                continue;
            }

            *e.pos++ = (u_char) (key_len & 0xff);
            *e.pos++ = (u_char) ((key_len >> 8) & 0xff);

            code = *(rp_http_script_code_pt *) e.ip;
            code((rp_http_script_engine_t *) &e);

            *e.pos++ = (u_char) (val_len & 0xff);
            *e.pos++ = (u_char) ((val_len >> 8) & 0xff);

            while (*(uintptr_t *) e.ip) {
                code = *(rp_http_script_code_pt *) e.ip;
                code((rp_http_script_engine_t *) &e);
            }

            e.ip += sizeof(uintptr_t);

            rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
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

            b->last = rp_cpymem(b->last, "HTTP_", sizeof("HTTP_") - 1);
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
            b->last = rp_copy(b->last, header[i].value.data, val_len);

            rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "uwsgi param: \"%*s: %*s\"",
                           key_len, b->last - (key_len + 2 + val_len),
                           val_len, b->last - val_len);
        next:

            continue;
        }
    }

    b->last = rp_copy(b->last, uwcf->uwsgi_string.data,
                       uwcf->uwsgi_string.len);

    if (r->request_body_no_buffering) {
        r->upstream->request_bufs = cl;

    } else if (uwcf->upstream.pass_request_body) {
        body = r->upstream->request_bufs;
        r->upstream->request_bufs = cl;

        while (body) {
            b = rp_alloc_buf(r->pool);
            if (b == NULL) {
                return RP_ERROR;
            }

            rp_memcpy(b, body->buf, sizeof(rp_buf_t));

            cl->next = rp_alloc_chain_link(r->pool);
            if (cl->next == NULL) {
                return RP_ERROR;
            }

            cl = cl->next;
            cl->buf = b;

            body = body->next;
        }

    } else {
        r->upstream->request_bufs = cl;
    }

    cl->next = NULL;

    return RP_OK;
}


static rp_int_t
rp_http_uwsgi_reinit_request(rp_http_request_t *r)
{
    rp_http_status_t  *status;

    status = rp_http_get_module_ctx(r, rp_http_uwsgi_module);

    if (status == NULL) {
        return RP_OK;
    }

    status->code = 0;
    status->count = 0;
    status->start = NULL;
    status->end = NULL;

    r->upstream->process_header = rp_http_uwsgi_process_status_line;
    r->state = 0;

    return RP_OK;
}


static rp_int_t
rp_http_uwsgi_process_status_line(rp_http_request_t *r)
{
    size_t                 len;
    rp_int_t              rc;
    rp_http_status_t     *status;
    rp_http_upstream_t   *u;

    status = rp_http_get_module_ctx(r, rp_http_uwsgi_module);

    if (status == NULL) {
        return RP_ERROR;
    }

    u = r->upstream;

    rc = rp_http_parse_status_line(r, &u->buffer, status);

    if (rc == RP_AGAIN) {
        return rc;
    }

    if (rc == RP_ERROR) {
        u->process_header = rp_http_uwsgi_process_header;
        return rp_http_uwsgi_process_header(r);
    }

    if (u->state && u->state->status == 0) {
        u->state->status = status->code;
    }

    u->headers_in.status_n = status->code;

    len = status->end - status->start;
    u->headers_in.status_line.len = len;

    u->headers_in.status_line.data = rp_pnalloc(r->pool, len);
    if (u->headers_in.status_line.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(u->headers_in.status_line.data, status->start, len);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http uwsgi status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    u->process_header = rp_http_uwsgi_process_header;

    return rp_http_uwsgi_process_header(r);
}


static rp_int_t
rp_http_uwsgi_process_header(rp_http_request_t *r)
{
    rp_str_t                      *status_line;
    rp_int_t                       rc, status;
    rp_table_elt_t                *h;
    rp_http_upstream_t            *u;
    rp_http_upstream_header_t     *hh;
    rp_http_upstream_main_conf_t  *umcf;

    umcf = rp_http_get_module_main_conf(r, rp_http_upstream_module);

    for ( ;; ) {

        rc = rp_http_parse_header_line(r, &r->upstream->buffer, 1);

        if (rc == RP_OK) {

            /* a header line has been parsed successfully */

            h = rp_list_push(&r->upstream->headers_in.headers);
            if (h == NULL) {
                return RP_ERROR;
            }

            h->hash = r->header_hash;

            h->key.len = r->header_name_end - r->header_name_start;
            h->value.len = r->header_end - r->header_start;

            h->key.data = rp_pnalloc(r->pool,
                                      h->key.len + 1 + h->value.len + 1
                                      + h->key.len);
            if (h->key.data == NULL) {
                h->hash = 0;
                return RP_ERROR;
            }

            h->value.data = h->key.data + h->key.len + 1;
            h->lowcase_key = h->key.data + h->key.len + 1 + h->value.len + 1;

            rp_memcpy(h->key.data, r->header_name_start, h->key.len);
            h->key.data[h->key.len] = '\0';
            rp_memcpy(h->value.data, r->header_start, h->value.len);
            h->value.data[h->value.len] = '\0';

            if (h->key.len == r->lowcase_index) {
                rp_memcpy(h->lowcase_key, r->lowcase_header, h->key.len);

            } else {
                rp_strlow(h->lowcase_key, h->key.data, h->key.len);
            }

            hh = rp_hash_find(&umcf->headers_in_hash, h->hash,
                               h->lowcase_key, h->key.len);

            if (hh && hh->handler(r, h, hh->offset) != RP_OK) {
                return RP_ERROR;
            }

            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http uwsgi header: \"%V: %V\"", &h->key, &h->value);

            continue;
        }

        if (rc == RP_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http uwsgi header done");

            u = r->upstream;

            if (u->headers_in.status_n) {
                goto done;
            }

            if (u->headers_in.status) {
                status_line = &u->headers_in.status->value;

                status = rp_atoi(status_line->data, 3);
                if (status == RP_ERROR) {
                    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                                  "upstream sent invalid status \"%V\"",
                                  status_line);
                    return RP_HTTP_UPSTREAM_INVALID_HEADER;
                }

                u->headers_in.status_n = status;
                u->headers_in.status_line = *status_line;

            } else if (u->headers_in.location) {
                u->headers_in.status_n = 302;
                rp_str_set(&u->headers_in.status_line,
                            "302 Moved Temporarily");

            } else {
                u->headers_in.status_n = 200;
                rp_str_set(&u->headers_in.status_line, "200 OK");
            }

            if (u->state && u->state->status == 0) {
                u->state->status = u->headers_in.status_n;
            }

        done:

            if (u->headers_in.status_n == RP_HTTP_SWITCHING_PROTOCOLS
                && r->headers_in.upgrade)
            {
                u->upgrade = 1;
            }

            return RP_OK;
        }

        if (rc == RP_AGAIN) {
            return RP_AGAIN;
        }

        /* there was error while a header line parsing */

        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "upstream sent invalid header");

        return RP_HTTP_UPSTREAM_INVALID_HEADER;
    }
}


static void
rp_http_uwsgi_abort_request(rp_http_request_t *r)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http uwsgi request");

    return;
}


static void
rp_http_uwsgi_finalize_request(rp_http_request_t *r, rp_int_t rc)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http uwsgi request");

    return;
}


static void *
rp_http_uwsgi_create_main_conf(rp_conf_t *cf)
{
    rp_http_uwsgi_main_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_uwsgi_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

#if (RP_HTTP_CACHE)
    if (rp_array_init(&conf->caches, cf->pool, 4,
                       sizeof(rp_http_file_cache_t *))
        != RP_OK)
    {
        return NULL;
    }
#endif

    return conf;
}


static void *
rp_http_uwsgi_create_loc_conf(rp_conf_t *cf)
{
    rp_http_uwsgi_loc_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_uwsgi_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->modifier1 = RP_CONF_UNSET_UINT;
    conf->modifier2 = RP_CONF_UNSET_UINT;

    conf->upstream.store = RP_CONF_UNSET;
    conf->upstream.store_access = RP_CONF_UNSET_UINT;
    conf->upstream.next_upstream_tries = RP_CONF_UNSET_UINT;
    conf->upstream.buffering = RP_CONF_UNSET;
    conf->upstream.request_buffering = RP_CONF_UNSET;
    conf->upstream.ignore_client_abort = RP_CONF_UNSET;
    conf->upstream.force_ranges = RP_CONF_UNSET;

    conf->upstream.local = RP_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = RP_CONF_UNSET;

    conf->upstream.connect_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = RP_CONF_UNSET_MSEC;

    conf->upstream.send_lowat = RP_CONF_UNSET_SIZE;
    conf->upstream.buffer_size = RP_CONF_UNSET_SIZE;
    conf->upstream.limit_rate = RP_CONF_UNSET_SIZE;

    conf->upstream.busy_buffers_size_conf = RP_CONF_UNSET_SIZE;
    conf->upstream.max_temp_file_size_conf = RP_CONF_UNSET_SIZE;
    conf->upstream.temp_file_write_size_conf = RP_CONF_UNSET_SIZE;

    conf->upstream.pass_request_headers = RP_CONF_UNSET;
    conf->upstream.pass_request_body = RP_CONF_UNSET;

#if (RP_HTTP_CACHE)
    conf->upstream.cache = RP_CONF_UNSET;
    conf->upstream.cache_min_uses = RP_CONF_UNSET_UINT;
    conf->upstream.cache_max_range_offset = RP_CONF_UNSET;
    conf->upstream.cache_bypass = RP_CONF_UNSET_PTR;
    conf->upstream.no_cache = RP_CONF_UNSET_PTR;
    conf->upstream.cache_valid = RP_CONF_UNSET_PTR;
    conf->upstream.cache_lock = RP_CONF_UNSET;
    conf->upstream.cache_lock_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.cache_lock_age = RP_CONF_UNSET_MSEC;
    conf->upstream.cache_revalidate = RP_CONF_UNSET;
    conf->upstream.cache_background_update = RP_CONF_UNSET;
#endif

    conf->upstream.hide_headers = RP_CONF_UNSET_PTR;
    conf->upstream.pass_headers = RP_CONF_UNSET_PTR;

    conf->upstream.intercept_errors = RP_CONF_UNSET;

#if (RP_HTTP_SSL)
    conf->upstream.ssl_session_reuse = RP_CONF_UNSET;
    conf->upstream.ssl_server_name = RP_CONF_UNSET;
    conf->upstream.ssl_verify = RP_CONF_UNSET;
    conf->ssl_verify_depth = RP_CONF_UNSET_UINT;
    conf->ssl_passwords = RP_CONF_UNSET_PTR;
#endif

    /* "uwsgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    rp_str_set(&conf->upstream.module, "uwsgi");

    return conf;
}


static char *
rp_http_uwsgi_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_uwsgi_loc_conf_t *prev = parent;
    rp_http_uwsgi_loc_conf_t *conf = child;

    size_t                        size;
    rp_int_t                     rc;
    rp_hash_init_t               hash;
    rp_http_core_loc_conf_t     *clcf;

#if (RP_HTTP_CACHE)

    if (conf->upstream.store > 0) {
        conf->upstream.cache = 0;
    }

    if (conf->upstream.cache > 0) {
        conf->upstream.store = 0;
    }

#endif

    if (conf->upstream.store == RP_CONF_UNSET) {
        rp_conf_merge_value(conf->upstream.store, prev->upstream.store, 0);

        conf->upstream.store_lengths = prev->upstream.store_lengths;
        conf->upstream.store_values = prev->upstream.store_values;
    }

    rp_conf_merge_uint_value(conf->upstream.store_access,
                              prev->upstream.store_access, 0600);

    rp_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    rp_conf_merge_value(conf->upstream.buffering,
                              prev->upstream.buffering, 1);

    rp_conf_merge_value(conf->upstream.request_buffering,
                              prev->upstream.request_buffering, 1);

    rp_conf_merge_value(conf->upstream.ignore_client_abort,
                              prev->upstream.ignore_client_abort, 0);

    rp_conf_merge_value(conf->upstream.force_ranges,
                              prev->upstream.force_ranges, 0);

    rp_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    rp_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    rp_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    rp_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    rp_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    rp_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    rp_conf_merge_size_value(conf->upstream.send_lowat,
                              prev->upstream.send_lowat, 0);

    rp_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) rp_pagesize);

    rp_conf_merge_size_value(conf->upstream.limit_rate,
                              prev->upstream.limit_rate, 0);


    rp_conf_merge_bufs_value(conf->upstream.bufs, prev->upstream.bufs,
                              8, rp_pagesize);

    if (conf->upstream.bufs.num < 2) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "there must be at least 2 \"uwsgi_buffers\"");
        return RP_CONF_ERROR;
    }


    size = conf->upstream.buffer_size;
    if (size < conf->upstream.bufs.size) {
        size = conf->upstream.bufs.size;
    }


    rp_conf_merge_size_value(conf->upstream.busy_buffers_size_conf,
                              prev->upstream.busy_buffers_size_conf,
                              RP_CONF_UNSET_SIZE);

    if (conf->upstream.busy_buffers_size_conf == RP_CONF_UNSET_SIZE) {
        conf->upstream.busy_buffers_size = 2 * size;
    } else {
        conf->upstream.busy_buffers_size =
            conf->upstream.busy_buffers_size_conf;
    }

    if (conf->upstream.busy_buffers_size < size) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
            "\"uwsgi_busy_buffers_size\" must be equal to or greater "
            "than the maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

        return RP_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
            "\"uwsgi_busy_buffers_size\" must be less than "
            "the size of all \"uwsgi_buffers\" minus one buffer");

        return RP_CONF_ERROR;
    }


    rp_conf_merge_size_value(conf->upstream.temp_file_write_size_conf,
                              prev->upstream.temp_file_write_size_conf,
                              RP_CONF_UNSET_SIZE);

    if (conf->upstream.temp_file_write_size_conf == RP_CONF_UNSET_SIZE) {
        conf->upstream.temp_file_write_size = 2 * size;
    } else {
        conf->upstream.temp_file_write_size =
            conf->upstream.temp_file_write_size_conf;
    }

    if (conf->upstream.temp_file_write_size < size) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
            "\"uwsgi_temp_file_write_size\" must be equal to or greater than "
            "the maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

        return RP_CONF_ERROR;
    }


    rp_conf_merge_size_value(conf->upstream.max_temp_file_size_conf,
                              prev->upstream.max_temp_file_size_conf,
                              RP_CONF_UNSET_SIZE);

    if (conf->upstream.max_temp_file_size_conf == RP_CONF_UNSET_SIZE) {
        conf->upstream.max_temp_file_size = 1024 * 1024 * 1024;
    } else {
        conf->upstream.max_temp_file_size =
            conf->upstream.max_temp_file_size_conf;
    }

    if (conf->upstream.max_temp_file_size != 0
        && conf->upstream.max_temp_file_size < size)
    {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
            "\"uwsgi_max_temp_file_size\" must be equal to zero to disable "
            "temporary files usage or must be equal to or greater than "
            "the maximum of the value of \"uwsgi_buffer_size\" and "
            "one of the \"uwsgi_buffers\"");

        return RP_CONF_ERROR;
    }


    rp_conf_merge_bitmask_value(conf->upstream.ignore_headers,
                                 prev->upstream.ignore_headers,
                                 RP_CONF_BITMASK_SET);


    rp_conf_merge_bitmask_value(conf->upstream.next_upstream,
                                 prev->upstream.next_upstream,
                                 (RP_CONF_BITMASK_SET
                                  |RP_HTTP_UPSTREAM_FT_ERROR
                                  |RP_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & RP_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = RP_CONF_BITMASK_SET
                                       |RP_HTTP_UPSTREAM_FT_OFF;
    }

    if (rp_conf_merge_path_value(cf, &conf->upstream.temp_path,
                                  prev->upstream.temp_path,
                                  &rp_http_uwsgi_temp_path)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

#if (RP_HTTP_CACHE)

    if (conf->upstream.cache == RP_CONF_UNSET) {
        rp_conf_merge_value(conf->upstream.cache,
                              prev->upstream.cache, 0);

        conf->upstream.cache_zone = prev->upstream.cache_zone;
        conf->upstream.cache_value = prev->upstream.cache_value;
    }

    if (conf->upstream.cache_zone && conf->upstream.cache_zone->data == NULL) {
        rp_shm_zone_t  *shm_zone;

        shm_zone = conf->upstream.cache_zone;

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "\"uwsgi_cache\" zone \"%V\" is unknown",
                           &shm_zone->shm.name);

        return RP_CONF_ERROR;
    }

    rp_conf_merge_uint_value(conf->upstream.cache_min_uses,
                              prev->upstream.cache_min_uses, 1);

    rp_conf_merge_off_value(conf->upstream.cache_max_range_offset,
                              prev->upstream.cache_max_range_offset,
                              RP_MAX_OFF_T_VALUE);

    rp_conf_merge_bitmask_value(conf->upstream.cache_use_stale,
                              prev->upstream.cache_use_stale,
                              (RP_CONF_BITMASK_SET
                               |RP_HTTP_UPSTREAM_FT_OFF));

    if (conf->upstream.cache_use_stale & RP_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.cache_use_stale = RP_CONF_BITMASK_SET
                                         |RP_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.cache_use_stale & RP_HTTP_UPSTREAM_FT_ERROR) {
        conf->upstream.cache_use_stale |= RP_HTTP_UPSTREAM_FT_NOLIVE;
    }

    if (conf->upstream.cache_methods == 0) {
        conf->upstream.cache_methods = prev->upstream.cache_methods;
    }

    conf->upstream.cache_methods |= RP_HTTP_GET|RP_HTTP_HEAD;

    rp_conf_merge_ptr_value(conf->upstream.cache_bypass,
                             prev->upstream.cache_bypass, NULL);

    rp_conf_merge_ptr_value(conf->upstream.no_cache,
                             prev->upstream.no_cache, NULL);

    rp_conf_merge_ptr_value(conf->upstream.cache_valid,
                             prev->upstream.cache_valid, NULL);

    if (conf->cache_key.value.data == NULL) {
        conf->cache_key = prev->cache_key;
    }

    if (conf->upstream.cache && conf->cache_key.value.data == NULL) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "no \"uwsgi_cache_key\" for \"uwsgi_cache\"");
    }

    rp_conf_merge_value(conf->upstream.cache_lock,
                              prev->upstream.cache_lock, 0);

    rp_conf_merge_msec_value(conf->upstream.cache_lock_timeout,
                              prev->upstream.cache_lock_timeout, 5000);

    rp_conf_merge_msec_value(conf->upstream.cache_lock_age,
                              prev->upstream.cache_lock_age, 5000);

    rp_conf_merge_value(conf->upstream.cache_revalidate,
                              prev->upstream.cache_revalidate, 0);

    rp_conf_merge_value(conf->upstream.cache_background_update,
                              prev->upstream.cache_background_update, 0);

#endif

    rp_conf_merge_value(conf->upstream.pass_request_headers,
                         prev->upstream.pass_request_headers, 1);
    rp_conf_merge_value(conf->upstream.pass_request_body,
                         prev->upstream.pass_request_body, 1);

    rp_conf_merge_value(conf->upstream.intercept_errors,
                         prev->upstream.intercept_errors, 0);

#if (RP_HTTP_SSL)

    rp_conf_merge_value(conf->upstream.ssl_session_reuse,
                              prev->upstream.ssl_session_reuse, 1);

    rp_conf_merge_bitmask_value(conf->ssl_protocols, prev->ssl_protocols,
                                 (RP_CONF_BITMASK_SET|RP_SSL_TLSv1
                                  |RP_SSL_TLSv1_1|RP_SSL_TLSv1_2));

    rp_conf_merge_str_value(conf->ssl_ciphers, prev->ssl_ciphers,
                             "DEFAULT");

    if (conf->upstream.ssl_name == NULL) {
        conf->upstream.ssl_name = prev->upstream.ssl_name;
    }

    rp_conf_merge_value(conf->upstream.ssl_server_name,
                              prev->upstream.ssl_server_name, 0);
    rp_conf_merge_value(conf->upstream.ssl_verify,
                              prev->upstream.ssl_verify, 0);
    rp_conf_merge_uint_value(conf->ssl_verify_depth,
                              prev->ssl_verify_depth, 1);
    rp_conf_merge_str_value(conf->ssl_trusted_certificate,
                              prev->ssl_trusted_certificate, "");
    rp_conf_merge_str_value(conf->ssl_crl, prev->ssl_crl, "");

    rp_conf_merge_str_value(conf->ssl_certificate,
                              prev->ssl_certificate, "");
    rp_conf_merge_str_value(conf->ssl_certificate_key,
                              prev->ssl_certificate_key, "");
    rp_conf_merge_ptr_value(conf->ssl_passwords, prev->ssl_passwords, NULL);

    if (conf->ssl && rp_http_uwsgi_set_ssl(cf, conf) != RP_OK) {
        return RP_CONF_ERROR;
    }

#endif

    rp_conf_merge_str_value(conf->uwsgi_string, prev->uwsgi_string, "");

    hash.max_size = 512;
    hash.bucket_size = rp_align(64, rp_cacheline_size);
    hash.name = "uwsgi_hide_headers_hash";

    if (rp_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, rp_http_uwsgi_hide_headers, &hash)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->uwsgi_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;

        conf->uwsgi_lengths = prev->uwsgi_lengths;
        conf->uwsgi_values = prev->uwsgi_values;

#if (RP_HTTP_SSL)
        conf->upstream.ssl = prev->upstream.ssl;
#endif
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->uwsgi_lengths))
    {
        clcf->handler = rp_http_uwsgi_handler;
    }

    rp_conf_merge_uint_value(conf->modifier1, prev->modifier1, 0);
    rp_conf_merge_uint_value(conf->modifier2, prev->modifier2, 0);

    if (conf->params_source == NULL) {
        conf->params = prev->params;
#if (RP_HTTP_CACHE)
        conf->params_cache = prev->params_cache;
#endif
        conf->params_source = prev->params_source;
    }

    rc = rp_http_uwsgi_init_params(cf, conf, &conf->params, NULL);
    if (rc != RP_OK) {
        return RP_CONF_ERROR;
    }

#if (RP_HTTP_CACHE)

    if (conf->upstream.cache) {
        rc = rp_http_uwsgi_init_params(cf, conf, &conf->params_cache,
                                        rp_http_uwsgi_cache_headers);
        if (rc != RP_OK) {
            return RP_CONF_ERROR;
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
#if (RP_HTTP_CACHE)
        prev->params_cache = conf->params_cache;
#endif
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_uwsgi_init_params(rp_conf_t *cf, rp_http_uwsgi_loc_conf_t *conf,
    rp_http_uwsgi_params_t *params, rp_keyval_t *default_params)
{
    u_char                       *p;
    size_t                        size;
    uintptr_t                    *code;
    rp_uint_t                    i, nsrc;
    rp_array_t                   headers_names, params_merged;
    rp_keyval_t                 *h;
    rp_hash_key_t               *hk;
    rp_hash_init_t               hash;
    rp_http_upstream_param_t    *src, *s;
    rp_http_script_compile_t     sc;
    rp_http_script_copy_code_t  *copy;

    if (params->hash.buckets) {
        return RP_OK;
    }

    if (conf->params_source == NULL && default_params == NULL) {
        params->hash.buckets = (void *) 1;
        return RP_OK;
    }

    params->lengths = rp_array_create(cf->pool, 64, 1);
    if (params->lengths == NULL) {
        return RP_ERROR;
    }

    params->values = rp_array_create(cf->pool, 512, 1);
    if (params->values == NULL) {
        return RP_ERROR;
    }

    if (rp_array_init(&headers_names, cf->temp_pool, 4, sizeof(rp_hash_key_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (conf->params_source) {
        src = conf->params_source->elts;
        nsrc = conf->params_source->nelts;

    } else {
        src = NULL;
        nsrc = 0;
    }

    if (default_params) {
        if (rp_array_init(&params_merged, cf->temp_pool, 4,
                           sizeof(rp_http_upstream_param_t))
            != RP_OK)
        {
            return RP_ERROR;
        }

        for (i = 0; i < nsrc; i++) {

            s = rp_array_push(&params_merged);
            if (s == NULL) {
                return RP_ERROR;
            }

            *s = src[i];
        }

        h = default_params;

        while (h->key.len) {

            src = params_merged.elts;
            nsrc = params_merged.nelts;

            for (i = 0; i < nsrc; i++) {
                if (rp_strcasecmp(h->key.data, src[i].key.data) == 0) {
                    goto next;
                }
            }

            s = rp_array_push(&params_merged);
            if (s == NULL) {
                return RP_ERROR;
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
            && rp_strncmp(src[i].key.data, "HTTP_", sizeof("HTTP_") - 1) == 0)
        {
            hk = rp_array_push(&headers_names);
            if (hk == NULL) {
                return RP_ERROR;
            }

            hk->key.len = src[i].key.len - 5;
            hk->key.data = src[i].key.data + 5;
            hk->key_hash = rp_hash_key_lc(hk->key.data, hk->key.len);
            hk->value = (void *) 1;

            if (src[i].value.len == 0) {
                continue;
            }
        }

        copy = rp_array_push_n(params->lengths,
                                sizeof(rp_http_script_copy_code_t));
        if (copy == NULL) {
            return RP_ERROR;
        }

        copy->code = (rp_http_script_code_pt) (void *)
                                                 rp_http_script_copy_len_code;
        copy->len = src[i].key.len;

        copy = rp_array_push_n(params->lengths,
                                sizeof(rp_http_script_copy_code_t));
        if (copy == NULL) {
            return RP_ERROR;
        }

        copy->code = (rp_http_script_code_pt) (void *)
                                                 rp_http_script_copy_len_code;
        copy->len = src[i].skip_empty;


        size = (sizeof(rp_http_script_copy_code_t)
                + src[i].key.len + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = rp_array_push_n(params->values, size);
        if (copy == NULL) {
            return RP_ERROR;
        }

        copy->code = rp_http_script_copy_code;
        copy->len = src[i].key.len;

        p = (u_char *) copy + sizeof(rp_http_script_copy_code_t);
        rp_memcpy(p, src[i].key.data, src[i].key.len);


        rp_memzero(&sc, sizeof(rp_http_script_compile_t));

        sc.cf = cf;
        sc.source = &src[i].value;
        sc.flushes = &params->flushes;
        sc.lengths = &params->lengths;
        sc.values = &params->values;

        if (rp_http_script_compile(&sc) != RP_OK) {
            return RP_ERROR;
        }

        code = rp_array_push_n(params->lengths, sizeof(uintptr_t));
        if (code == NULL) {
            return RP_ERROR;
        }

        *code = (uintptr_t) NULL;


        code = rp_array_push_n(params->values, sizeof(uintptr_t));
        if (code == NULL) {
            return RP_ERROR;
        }

        *code = (uintptr_t) NULL;
    }

    code = rp_array_push_n(params->lengths, sizeof(uintptr_t));
    if (code == NULL) {
        return RP_ERROR;
    }

    *code = (uintptr_t) NULL;

    params->number = headers_names.nelts;

    hash.hash = &params->hash;
    hash.key = rp_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = 64;
    hash.name = "uwsgi_params_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return rp_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
rp_http_uwsgi_pass(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_uwsgi_loc_conf_t *uwcf = conf;

    size_t                      add;
    rp_url_t                   u;
    rp_str_t                  *value, *url;
    rp_uint_t                  n;
    rp_http_core_loc_conf_t   *clcf;
    rp_http_script_compile_t   sc;

    if (uwcf->upstream.upstream || uwcf->uwsgi_lengths) {
        return "is duplicate";
    }

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);
    clcf->handler = rp_http_uwsgi_handler;

    value = cf->args->elts;

    url = &value[1];

    n = rp_http_script_variables_count(url);

    if (n) {

        rp_memzero(&sc, sizeof(rp_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &uwcf->uwsgi_lengths;
        sc.values = &uwcf->uwsgi_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rp_http_script_compile(&sc) != RP_OK) {
            return RP_CONF_ERROR;
        }

#if (RP_HTTP_SSL)
        uwcf->ssl = 1;
#endif

        return RP_CONF_OK;
    }

    if (rp_strncasecmp(url->data, (u_char *) "uwsgi://", 8) == 0) {
        add = 8;

    } else if (rp_strncasecmp(url->data, (u_char *) "suwsgi://", 9) == 0) {

#if (RP_HTTP_SSL)
        add = 9;
        uwcf->ssl = 1;
#else
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "suwsgi protocol requires SSL support");
        return RP_CONF_ERROR;
#endif

    } else {
        add = 0;
    }

    rp_memzero(&u, sizeof(rp_url_t));

    u.url.len = url->len - add;
    u.url.data = url->data + add;
    u.no_resolve = 1;

    uwcf->upstream.upstream = rp_http_upstream_add(cf, &u, 0);
    if (uwcf->upstream.upstream == NULL) {
        return RP_CONF_ERROR;
    }

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return RP_CONF_OK;
}


static char *
rp_http_uwsgi_store(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_uwsgi_loc_conf_t *uwcf = conf;

    rp_str_t                  *value;
    rp_http_script_compile_t   sc;

    if (uwcf->upstream.store != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "off") == 0) {
        uwcf->upstream.store = 0;
        return RP_CONF_OK;
    }

#if (RP_HTTP_CACHE)

    if (uwcf->upstream.cache > 0) {
        return "is incompatible with \"uwsgi_cache\"";
    }

#endif

    uwcf->upstream.store = 1;

    if (rp_strcmp(value[1].data, "on") == 0) {
        return RP_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    rp_memzero(&sc, sizeof(rp_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &uwcf->upstream.store_lengths;
    sc.values = &uwcf->upstream.store_values;
    sc.variables = rp_http_script_variables_count(&value[1]);
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (rp_http_script_compile(&sc) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


#if (RP_HTTP_CACHE)

static char *
rp_http_uwsgi_cache(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_uwsgi_loc_conf_t *uwcf = conf;

    rp_str_t                         *value;
    rp_http_complex_value_t           cv;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (uwcf->upstream.cache != RP_CONF_UNSET) {
        return "is duplicate";
    }

    if (rp_strcmp(value[1].data, "off") == 0) {
        uwcf->upstream.cache = 0;
        return RP_CONF_OK;
    }

    if (uwcf->upstream.store > 0) {
        return "is incompatible with \"uwsgi_store\"";
    }

    uwcf->upstream.cache = 1;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        uwcf->upstream.cache_value = rp_palloc(cf->pool,
                                             sizeof(rp_http_complex_value_t));
        if (uwcf->upstream.cache_value == NULL) {
            return RP_CONF_ERROR;
        }

        *uwcf->upstream.cache_value = cv;

        return RP_CONF_OK;
    }

    uwcf->upstream.cache_zone = rp_shared_memory_add(cf, &value[1], 0,
                                                      &rp_http_uwsgi_module);
    if (uwcf->upstream.cache_zone == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_http_uwsgi_cache_key(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_uwsgi_loc_conf_t *uwcf = conf;

    rp_str_t                         *value;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (uwcf->cache_key.value.data) {
        return "is duplicate";
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &uwcf->cache_key;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}

#endif


#if (RP_HTTP_SSL)

static char *
rp_http_uwsgi_ssl_password_file(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_uwsgi_loc_conf_t *uwcf = conf;

    rp_str_t  *value;

    if (uwcf->ssl_passwords != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    uwcf->ssl_passwords = rp_ssl_read_password_file(cf, &value[1]);

    if (uwcf->ssl_passwords == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_uwsgi_set_ssl(rp_conf_t *cf, rp_http_uwsgi_loc_conf_t *uwcf)
{
    rp_pool_cleanup_t  *cln;

    uwcf->upstream.ssl = rp_pcalloc(cf->pool, sizeof(rp_ssl_t));
    if (uwcf->upstream.ssl == NULL) {
        return RP_ERROR;
    }

    uwcf->upstream.ssl->log = cf->log;

    if (rp_ssl_create(uwcf->upstream.ssl, uwcf->ssl_protocols, NULL)
        != RP_OK)
    {
        return RP_ERROR;
    }

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        rp_ssl_cleanup_ctx(uwcf->upstream.ssl);
        return RP_ERROR;
    }

    cln->handler = rp_ssl_cleanup_ctx;
    cln->data = uwcf->upstream.ssl;

    if (uwcf->ssl_certificate.len) {

        if (uwcf->ssl_certificate_key.len == 0) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "no \"uwsgi_ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &uwcf->ssl_certificate);
            return RP_ERROR;
        }

        if (rp_ssl_certificate(cf, uwcf->upstream.ssl, &uwcf->ssl_certificate,
                                &uwcf->ssl_certificate_key, uwcf->ssl_passwords)
            != RP_OK)
        {
            return RP_ERROR;
        }
    }

    if (rp_ssl_ciphers(cf, uwcf->upstream.ssl, &uwcf->ssl_ciphers, 0)
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (uwcf->upstream.ssl_verify) {
        if (uwcf->ssl_trusted_certificate.len == 0) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no uwsgi_ssl_trusted_certificate for uwsgi_ssl_verify");
            return RP_ERROR;
        }

        if (rp_ssl_trusted_certificate(cf, uwcf->upstream.ssl,
                                        &uwcf->ssl_trusted_certificate,
                                        uwcf->ssl_verify_depth)
            != RP_OK)
        {
            return RP_ERROR;
        }

        if (rp_ssl_crl(cf, uwcf->upstream.ssl, &uwcf->ssl_crl) != RP_OK) {
            return RP_ERROR;
        }
    }

    if (rp_ssl_client_session_cache(cf, uwcf->upstream.ssl,
                                     uwcf->upstream.ssl_session_reuse)
        != RP_OK)
    {
        return RP_ERROR;
    }

    return RP_OK;
}

#endif
