
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 * Copyright (C) Manlio Perillo (manlio.perillo@gmail.com)
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_array_t                caches;  /* rp_http_file_cache_t * */
} rp_http_scgi_main_conf_t;


typedef struct {
    rp_array_t               *flushes;
    rp_array_t               *lengths;
    rp_array_t               *values;
    rp_uint_t                 number;
    rp_hash_t                 hash;
} rp_http_scgi_params_t;


typedef struct {
    rp_http_upstream_conf_t   upstream;

    rp_http_scgi_params_t     params;
#if (RP_HTTP_CACHE)
    rp_http_scgi_params_t     params_cache;
#endif
    rp_array_t               *params_source;

    rp_array_t               *scgi_lengths;
    rp_array_t               *scgi_values;

#if (RP_HTTP_CACHE)
    rp_http_complex_value_t   cache_key;
#endif
} rp_http_scgi_loc_conf_t;


static rp_int_t rp_http_scgi_eval(rp_http_request_t *r,
    rp_http_scgi_loc_conf_t *scf);
static rp_int_t rp_http_scgi_create_request(rp_http_request_t *r);
static rp_int_t rp_http_scgi_reinit_request(rp_http_request_t *r);
static rp_int_t rp_http_scgi_process_status_line(rp_http_request_t *r);
static rp_int_t rp_http_scgi_process_header(rp_http_request_t *r);
static void rp_http_scgi_abort_request(rp_http_request_t *r);
static void rp_http_scgi_finalize_request(rp_http_request_t *r, rp_int_t rc);

static void *rp_http_scgi_create_main_conf(rp_conf_t *cf);
static void *rp_http_scgi_create_loc_conf(rp_conf_t *cf);
static char *rp_http_scgi_merge_loc_conf(rp_conf_t *cf, void *parent,
    void *child);
static rp_int_t rp_http_scgi_init_params(rp_conf_t *cf,
    rp_http_scgi_loc_conf_t *conf, rp_http_scgi_params_t *params,
    rp_keyval_t *default_params);

static char *rp_http_scgi_pass(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_http_scgi_store(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);

#if (RP_HTTP_CACHE)
static rp_int_t rp_http_scgi_create_key(rp_http_request_t *r);
static char *rp_http_scgi_cache(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_scgi_cache_key(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
#endif


static rp_conf_bitmask_t rp_http_scgi_next_upstream_masks[] = {
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


rp_module_t  rp_http_scgi_module;


static rp_command_t rp_http_scgi_commands[] = {

    { rp_string("scgi_pass"),
      RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF|RP_CONF_TAKE1,
      rp_http_scgi_pass,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("scgi_store"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_scgi_store,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("scgi_store_access"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE123,
      rp_conf_set_access_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.store_access),
      NULL },

    { rp_string("scgi_buffering"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.buffering),
      NULL },

    { rp_string("scgi_request_buffering"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.request_buffering),
      NULL },

    { rp_string("scgi_ignore_client_abort"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.ignore_client_abort),
      NULL },

    { rp_string("scgi_bind"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE12,
      rp_http_upstream_bind_set_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.local),
      NULL },

    { rp_string("scgi_socket_keepalive"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { rp_string("scgi_connect_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.connect_timeout),
      NULL },

    { rp_string("scgi_send_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.send_timeout),
      NULL },

    { rp_string("scgi_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.buffer_size),
      NULL },

    { rp_string("scgi_pass_request_headers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.pass_request_headers),
      NULL },

    { rp_string("scgi_pass_request_body"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.pass_request_body),
      NULL },

    { rp_string("scgi_intercept_errors"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.intercept_errors),
      NULL },

    { rp_string("scgi_read_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.read_timeout),
      NULL },

    { rp_string("scgi_buffers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_conf_set_bufs_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.bufs),
      NULL },

    { rp_string("scgi_busy_buffers_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.busy_buffers_size_conf),
      NULL },

    { rp_string("scgi_force_ranges"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.force_ranges),
      NULL },

    { rp_string("scgi_limit_rate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.limit_rate),
      NULL },

#if (RP_HTTP_CACHE)

    { rp_string("scgi_cache"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_scgi_cache,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("scgi_cache_key"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_scgi_cache_key,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("scgi_cache_path"),
      RP_HTTP_MAIN_CONF|RP_CONF_2MORE,
      rp_http_file_cache_set_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_scgi_main_conf_t, caches),
      &rp_http_scgi_module },

    { rp_string("scgi_cache_bypass"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_set_predicate_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_bypass),
      NULL },

    { rp_string("scgi_no_cache"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_set_predicate_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.no_cache),
      NULL },

    { rp_string("scgi_cache_valid"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_file_cache_valid_set_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_valid),
      NULL },

    { rp_string("scgi_cache_min_uses"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_min_uses),
      NULL },

    { rp_string("scgi_cache_max_range_offset"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_off_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_max_range_offset),
      NULL },

    { rp_string("scgi_cache_use_stale"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_use_stale),
      &rp_http_scgi_next_upstream_masks },

    { rp_string("scgi_cache_methods"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_methods),
      &rp_http_upstream_cache_method_mask },

    { rp_string("scgi_cache_lock"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_lock),
      NULL },

    { rp_string("scgi_cache_lock_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_lock_timeout),
      NULL },

    { rp_string("scgi_cache_lock_age"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_lock_age),
      NULL },

    { rp_string("scgi_cache_revalidate"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_revalidate),
      NULL },

    { rp_string("scgi_cache_background_update"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.cache_background_update),
      NULL },

#endif

    { rp_string("scgi_temp_path"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1234,
      rp_conf_set_path_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.temp_path),
      NULL },

    { rp_string("scgi_max_temp_file_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.max_temp_file_size_conf),
      NULL },

    { rp_string("scgi_temp_file_write_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.temp_file_write_size_conf),
      NULL },

    { rp_string("scgi_next_upstream"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.next_upstream),
      &rp_http_scgi_next_upstream_masks },

    { rp_string("scgi_next_upstream_tries"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { rp_string("scgi_next_upstream_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { rp_string("scgi_param"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE23,
      rp_http_upstream_param_set_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, params_source),
      NULL },

    { rp_string("scgi_pass_header"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.pass_headers),
      NULL },

    { rp_string("scgi_hide_header"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.hide_headers),
      NULL },

    { rp_string("scgi_ignore_headers"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_scgi_loc_conf_t, upstream.ignore_headers),
      &rp_http_upstream_ignore_headers_masks },

      rp_null_command
};


static rp_http_module_t rp_http_scgi_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rp_http_scgi_create_main_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_scgi_create_loc_conf,         /* create location configuration */
    rp_http_scgi_merge_loc_conf           /* merge location configuration */
};


rp_module_t rp_http_scgi_module = {
    RP_MODULE_V1,
    &rp_http_scgi_module_ctx,             /* module context */
    rp_http_scgi_commands,                /* module directives */
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


static rp_str_t rp_http_scgi_hide_headers[] = {
    rp_string("Status"),
    rp_string("X-Accel-Expires"),
    rp_string("X-Accel-Redirect"),
    rp_string("X-Accel-Limit-Rate"),
    rp_string("X-Accel-Buffering"),
    rp_string("X-Accel-Charset"),
    rp_null_string
};


#if (RP_HTTP_CACHE)

static rp_keyval_t  rp_http_scgi_cache_headers[] = {
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


static rp_path_init_t rp_http_scgi_temp_path = {
    rp_string(RP_HTTP_SCGI_TEMP_PATH), { 1, 2, 0 }
};


static rp_int_t
rp_http_scgi_handler(rp_http_request_t *r)
{
    rp_int_t                   rc;
    rp_http_status_t          *status;
    rp_http_upstream_t        *u;
    rp_http_scgi_loc_conf_t   *scf;
#if (RP_HTTP_CACHE)
    rp_http_scgi_main_conf_t  *smcf;
#endif

    if (rp_http_upstream_create(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    status = rp_pcalloc(r->pool, sizeof(rp_http_status_t));
    if (status == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rp_http_set_ctx(r, status, rp_http_scgi_module);

    scf = rp_http_get_module_loc_conf(r, rp_http_scgi_module);

    if (scf->scgi_lengths) {
        if (rp_http_scgi_eval(r, scf) != RP_OK) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    u = r->upstream;

    rp_str_set(&u->schema, "scgi://");
    u->output.tag = (rp_buf_tag_t) &rp_http_scgi_module;

    u->conf = &scf->upstream;

#if (RP_HTTP_CACHE)
    smcf = rp_http_get_module_main_conf(r, rp_http_scgi_module);

    u->caches = &smcf->caches;
    u->create_key = rp_http_scgi_create_key;
#endif

    u->create_request = rp_http_scgi_create_request;
    u->reinit_request = rp_http_scgi_reinit_request;
    u->process_header = rp_http_scgi_process_status_line;
    u->abort_request = rp_http_scgi_abort_request;
    u->finalize_request = rp_http_scgi_finalize_request;
    r->state = 0;

    u->buffering = scf->upstream.buffering;

    u->pipe = rp_pcalloc(r->pool, sizeof(rp_event_pipe_t));
    if (u->pipe == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    u->pipe->input_filter = rp_event_pipe_copy_input_filter;
    u->pipe->input_ctx = r;

    if (!scf->upstream.request_buffering
        && scf->upstream.pass_request_body
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
rp_http_scgi_eval(rp_http_request_t *r, rp_http_scgi_loc_conf_t * scf)
{
    rp_url_t             url;
    rp_http_upstream_t  *u;

    rp_memzero(&url, sizeof(rp_url_t));

    if (rp_http_script_run(r, &url.url, scf->scgi_lengths->elts, 0,
                            scf->scgi_values->elts)
        == NULL)
    {
        return RP_ERROR;
    }

    url.no_resolve = 1;

    if (rp_parse_url(r->pool, &url) != RP_OK) {
        if (url.err) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return RP_ERROR;
    }

    u = r->upstream;

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
rp_http_scgi_create_key(rp_http_request_t *r)
{
    rp_str_t                 *key;
    rp_http_scgi_loc_conf_t  *scf;

    key = rp_array_push(&r->cache->keys);
    if (key == NULL) {
        return RP_ERROR;
    }

    scf = rp_http_get_module_loc_conf(r, rp_http_scgi_module);

    if (rp_http_complex_value(r, &scf->cache_key, key) != RP_OK) {
        return RP_ERROR;
    }

    return RP_OK;
}

#endif


static rp_int_t
rp_http_scgi_create_request(rp_http_request_t *r)
{
    off_t                         content_length_n;
    u_char                        ch, *key, *val, *lowcase_key;
    size_t                        len, key_len, val_len, allocated;
    rp_buf_t                    *b;
    rp_str_t                     content_length;
    rp_uint_t                    i, n, hash, skip_empty, header_params;
    rp_chain_t                  *cl, *body;
    rp_list_part_t              *part;
    rp_table_elt_t              *header, **ignored;
    rp_http_scgi_params_t       *params;
    rp_http_script_code_pt       code;
    rp_http_script_engine_t      e, le;
    rp_http_scgi_loc_conf_t     *scf;
    rp_http_script_len_code_pt   lcode;
    u_char                        buffer[RP_OFF_T_LEN];

    content_length_n = 0;
    body = r->upstream->request_bufs;

    while (body) {
        content_length_n += rp_buf_size(body->buf);
        body = body->next;
    }

    content_length.data = buffer;
    content_length.len = rp_sprintf(buffer, "%O", content_length_n) - buffer;

    len = sizeof("CONTENT_LENGTH") + content_length.len + 1;

    header_params = 0;
    ignored = NULL;

    scf = rp_http_get_module_loc_conf(r, rp_http_scgi_module);

#if (RP_HTTP_CACHE)
    params = r->upstream->cacheable ? &scf->params_cache : &scf->params;
#else
    params = &scf->params;
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

            len += key_len + val_len + 1;
        }
    }

    if (scf->upstream.pass_request_headers) {

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

        for (i = 0; /* void */; i++) {

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

            len += sizeof("HTTP_") - 1 + header[i].key.len + 1
                + header[i].value.len + 1;
        }
    }

    /* netstring: "length:" + packet + "," */

    b = rp_create_temp_buf(r->pool, RP_SIZE_T_LEN + 1 + len + 1);
    if (b == NULL) {
        return RP_ERROR;
    }

    cl = rp_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RP_ERROR;
    }

    cl->buf = b;

    b->last = rp_sprintf(b->last, "%ui:CONTENT_LENGTH%Z%V%Z",
                          len, &content_length);

    if (params->lengths) {
        rp_memzero(&e, sizeof(rp_http_script_engine_t));

        e.ip = params->values->elts;
        e.pos = b->last;
        e.request = r;
        e.flushed = 1;

        le.ip = params->lengths->elts;

        while (*(uintptr_t *) le.ip) {

            lcode = *(rp_http_script_len_code_pt *) le.ip;
            lcode(&le); /* key length */

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

#if (RP_DEBUG)
            key = e.pos;
#endif
            code = *(rp_http_script_code_pt *) e.ip;
            code((rp_http_script_engine_t *) &e);

#if (RP_DEBUG)
            val = e.pos;
#endif
            while (*(uintptr_t *) e.ip) {
                code = *(rp_http_script_code_pt *) e.ip;
                code((rp_http_script_engine_t *) &e);
            }
            *e.pos++ = '\0';
            e.ip += sizeof(uintptr_t);

            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "scgi param: \"%s: %s\"", key, val);
        }

        b->last = e.pos;
    }

    if (scf->upstream.pass_request_headers) {

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

            for (n = 0; n < header_params; n++) {
                if (&header[i] == ignored[n]) {
                    goto next;
                }
            }

            key = b->last;
            b->last = rp_cpymem(key, "HTTP_", sizeof("HTTP_") - 1);

            for (n = 0; n < header[i].key.len; n++) {
                ch = header[i].key.data[n];

                if (ch >= 'a' && ch <= 'z') {
                    ch &= ~0x20;

                } else if (ch == '-') {
                    ch = '_';
                }

                *b->last++ = ch;
            }

            *b->last++ = (u_char) 0;

            val = b->last;
            b->last = rp_copy(val, header[i].value.data, header[i].value.len);
            *b->last++ = (u_char) 0;

            rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "scgi param: \"%s: %s\"", key, val);

        next:

            continue;
        }
    }

    *b->last++ = (u_char) ',';

    if (r->request_body_no_buffering) {
        r->upstream->request_bufs = cl;

    } else if (scf->upstream.pass_request_body) {
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
rp_http_scgi_reinit_request(rp_http_request_t *r)
{
    rp_http_status_t  *status;

    status = rp_http_get_module_ctx(r, rp_http_scgi_module);

    if (status == NULL) {
        return RP_OK;
    }

    status->code = 0;
    status->count = 0;
    status->start = NULL;
    status->end = NULL;

    r->upstream->process_header = rp_http_scgi_process_status_line;
    r->state = 0;

    return RP_OK;
}


static rp_int_t
rp_http_scgi_process_status_line(rp_http_request_t *r)
{
    size_t                len;
    rp_int_t             rc;
    rp_http_status_t    *status;
    rp_http_upstream_t  *u;

    status = rp_http_get_module_ctx(r, rp_http_scgi_module);

    if (status == NULL) {
        return RP_ERROR;
    }

    u = r->upstream;

    rc = rp_http_parse_status_line(r, &u->buffer, status);

    if (rc == RP_AGAIN) {
        return rc;
    }

    if (rc == RP_ERROR) {
        u->process_header = rp_http_scgi_process_header;
        return rp_http_scgi_process_header(r);
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
                   "http scgi status %ui \"%V\"",
                   u->headers_in.status_n, &u->headers_in.status_line);

    u->process_header = rp_http_scgi_process_header;

    return rp_http_scgi_process_header(r);
}


static rp_int_t
rp_http_scgi_process_header(rp_http_request_t *r)
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
                           "http scgi header: \"%V: %V\"", &h->key, &h->value);

            continue;
        }

        if (rc == RP_HTTP_PARSE_HEADER_DONE) {

            /* a whole header has been parsed successfully */

            rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http scgi header done");

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
rp_http_scgi_abort_request(rp_http_request_t *r)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http scgi request");

    return;
}


static void
rp_http_scgi_finalize_request(rp_http_request_t *r, rp_int_t rc)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http scgi request");

    return;
}


static void *
rp_http_scgi_create_main_conf(rp_conf_t *cf)
{
    rp_http_scgi_main_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_scgi_main_conf_t));
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
rp_http_scgi_create_loc_conf(rp_conf_t *cf)
{
    rp_http_scgi_loc_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_scgi_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

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

    /* "scgi_cyclic_temp_file" is disabled */
    conf->upstream.cyclic_temp_file = 0;

    conf->upstream.change_buffering = 1;

    rp_str_set(&conf->upstream.module, "scgi");

    return conf;
}


static char *
rp_http_scgi_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_scgi_loc_conf_t *prev = parent;
    rp_http_scgi_loc_conf_t *conf = child;

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
                           "there must be at least 2 \"scgi_buffers\"");
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
            "\"scgi_busy_buffers_size\" must be equal to or greater "
            "than the maximum of the value of \"scgi_buffer_size\" and "
            "one of the \"scgi_buffers\"");

        return RP_CONF_ERROR;
    }

    if (conf->upstream.busy_buffers_size
        > (conf->upstream.bufs.num - 1) * conf->upstream.bufs.size)
    {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
            "\"scgi_busy_buffers_size\" must be less than "
            "the size of all \"scgi_buffers\" minus one buffer");

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
            "\"scgi_temp_file_write_size\" must be equal to or greater than "
            "the maximum of the value of \"scgi_buffer_size\" and "
            "one of the \"scgi_buffers\"");

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
            "\"scgi_max_temp_file_size\" must be equal to zero to disable "
            "temporary files usage or must be equal to or greater than "
            "the maximum of the value of \"scgi_buffer_size\" and "
            "one of the \"scgi_buffers\"");

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
                                  &rp_http_scgi_temp_path)
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
                           "\"scgi_cache\" zone \"%V\" is unknown",
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
                           "no \"scgi_cache_key\" for \"scgi_cache\"");
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

    hash.max_size = 512;
    hash.bucket_size = rp_align(64, rp_cacheline_size);
    hash.name = "scgi_hide_headers_hash";

    if (rp_http_upstream_hide_headers_hash(cf, &conf->upstream,
            &prev->upstream, rp_http_scgi_hide_headers, &hash)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);

    if (clcf->noname
        && conf->upstream.upstream == NULL && conf->scgi_lengths == NULL)
    {
        conf->upstream.upstream = prev->upstream.upstream;
        conf->scgi_lengths = prev->scgi_lengths;
        conf->scgi_values = prev->scgi_values;
    }

    if (clcf->lmt_excpt && clcf->handler == NULL
        && (conf->upstream.upstream || conf->scgi_lengths))
    {
        clcf->handler = rp_http_scgi_handler;
    }

    if (conf->params_source == NULL) {
        conf->params = prev->params;
#if (RP_HTTP_CACHE)
        conf->params_cache = prev->params_cache;
#endif
        conf->params_source = prev->params_source;
    }

    rc = rp_http_scgi_init_params(cf, conf, &conf->params, NULL);
    if (rc != RP_OK) {
        return RP_CONF_ERROR;
    }

#if (RP_HTTP_CACHE)

    if (conf->upstream.cache) {
        rc = rp_http_scgi_init_params(cf, conf, &conf->params_cache,
                                       rp_http_scgi_cache_headers);
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
rp_http_scgi_init_params(rp_conf_t *cf, rp_http_scgi_loc_conf_t *conf,
    rp_http_scgi_params_t *params, rp_keyval_t *default_params)
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
        copy->len = src[i].key.len + 1;

        copy = rp_array_push_n(params->lengths,
                                sizeof(rp_http_script_copy_code_t));
        if (copy == NULL) {
            return RP_ERROR;
        }

        copy->code = (rp_http_script_code_pt) (void *)
                                                 rp_http_script_copy_len_code;
        copy->len = src[i].skip_empty;


        size = (sizeof(rp_http_script_copy_code_t)
                + src[i].key.len + 1 + sizeof(uintptr_t) - 1)
               & ~(sizeof(uintptr_t) - 1);

        copy = rp_array_push_n(params->values, size);
        if (copy == NULL) {
            return RP_ERROR;
        }

        copy->code = rp_http_script_copy_code;
        copy->len = src[i].key.len + 1;

        p = (u_char *) copy + sizeof(rp_http_script_copy_code_t);
        (void) rp_cpystrn(p, src[i].key.data, src[i].key.len + 1);


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
    hash.name = "scgi_params_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    return rp_hash_init(&hash, headers_names.elts, headers_names.nelts);
}


static char *
rp_http_scgi_pass(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_scgi_loc_conf_t *scf = conf;

    rp_url_t                   u;
    rp_str_t                  *value, *url;
    rp_uint_t                  n;
    rp_http_core_loc_conf_t   *clcf;
    rp_http_script_compile_t   sc;

    if (scf->upstream.upstream || scf->scgi_lengths) {
        return "is duplicate";
    }

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);
    clcf->handler = rp_http_scgi_handler;

    value = cf->args->elts;

    url = &value[1];

    n = rp_http_script_variables_count(url);

    if (n) {

        rp_memzero(&sc, sizeof(rp_http_script_compile_t));

        sc.cf = cf;
        sc.source = url;
        sc.lengths = &scf->scgi_lengths;
        sc.values = &scf->scgi_values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (rp_http_script_compile(&sc) != RP_OK) {
            return RP_CONF_ERROR;
        }

        return RP_CONF_OK;
    }

    rp_memzero(&u, sizeof(rp_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    scf->upstream.upstream = rp_http_upstream_add(cf, &u, 0);
    if (scf->upstream.upstream == NULL) {
        return RP_CONF_ERROR;
    }

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    return RP_CONF_OK;
}


static char *
rp_http_scgi_store(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_scgi_loc_conf_t *scf = conf;

    rp_str_t                  *value;
    rp_http_script_compile_t   sc;

    if (scf->upstream.store != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "off") == 0) {
        scf->upstream.store = 0;
        return RP_CONF_OK;
    }

#if (RP_HTTP_CACHE)
    if (scf->upstream.cache > 0) {
        return "is incompatible with \"scgi_cache\"";
    }
#endif

    scf->upstream.store = 1;

    if (rp_strcmp(value[1].data, "on") == 0) {
        return RP_CONF_OK;
    }

    /* include the terminating '\0' into script */
    value[1].len++;

    rp_memzero(&sc, sizeof(rp_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &scf->upstream.store_lengths;
    sc.values = &scf->upstream.store_values;
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
rp_http_scgi_cache(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_scgi_loc_conf_t *scf = conf;

    rp_str_t                         *value;
    rp_http_complex_value_t           cv;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (scf->upstream.cache != RP_CONF_UNSET) {
        return "is duplicate";
    }

    if (rp_strcmp(value[1].data, "off") == 0) {
        scf->upstream.cache = 0;
        return RP_CONF_OK;
    }

    if (scf->upstream.store > 0) {
        return "is incompatible with \"scgi_store\"";
    }

    scf->upstream.cache = 1;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        scf->upstream.cache_value = rp_palloc(cf->pool,
                                             sizeof(rp_http_complex_value_t));
        if (scf->upstream.cache_value == NULL) {
            return RP_CONF_ERROR;
        }

        *scf->upstream.cache_value = cv;

        return RP_CONF_OK;
    }

    scf->upstream.cache_zone = rp_shared_memory_add(cf, &value[1], 0,
                                                     &rp_http_scgi_module);
    if (scf->upstream.cache_zone == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_http_scgi_cache_key(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_scgi_loc_conf_t *scf = conf;

    rp_str_t                         *value;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (scf->cache_key.value.data) {
        return "is duplicate";
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &scf->cache_key;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}

#endif
