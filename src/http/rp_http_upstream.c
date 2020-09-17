
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#if (RP_HTTP_CACHE)
static rp_int_t rp_http_upstream_cache(rp_http_request_t *r,
    rp_http_upstream_t *u);
static rp_int_t rp_http_upstream_cache_get(rp_http_request_t *r,
    rp_http_upstream_t *u, rp_http_file_cache_t **cache);
static rp_int_t rp_http_upstream_cache_send(rp_http_request_t *r,
    rp_http_upstream_t *u);
static rp_int_t rp_http_upstream_cache_background_update(
    rp_http_request_t *r, rp_http_upstream_t *u);
static rp_int_t rp_http_upstream_cache_check_range(rp_http_request_t *r,
    rp_http_upstream_t *u);
static rp_int_t rp_http_upstream_cache_status(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_upstream_cache_last_modified(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_upstream_cache_etag(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
#endif

static void rp_http_upstream_init_request(rp_http_request_t *r);
static void rp_http_upstream_resolve_handler(rp_resolver_ctx_t *ctx);
static void rp_http_upstream_rd_check_broken_connection(rp_http_request_t *r);
static void rp_http_upstream_wr_check_broken_connection(rp_http_request_t *r);
static void rp_http_upstream_check_broken_connection(rp_http_request_t *r,
    rp_event_t *ev);
static void rp_http_upstream_connect(rp_http_request_t *r,
    rp_http_upstream_t *u);
static rp_int_t rp_http_upstream_reinit(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_send_request(rp_http_request_t *r,
    rp_http_upstream_t *u, rp_uint_t do_write);
static rp_int_t rp_http_upstream_send_request_body(rp_http_request_t *r,
    rp_http_upstream_t *u, rp_uint_t do_write);
static void rp_http_upstream_send_request_handler(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_read_request_handler(rp_http_request_t *r);
static void rp_http_upstream_process_header(rp_http_request_t *r,
    rp_http_upstream_t *u);
static rp_int_t rp_http_upstream_test_next(rp_http_request_t *r,
    rp_http_upstream_t *u);
static rp_int_t rp_http_upstream_intercept_errors(rp_http_request_t *r,
    rp_http_upstream_t *u);
static rp_int_t rp_http_upstream_test_connect(rp_connection_t *c);
static rp_int_t rp_http_upstream_process_headers(rp_http_request_t *r,
    rp_http_upstream_t *u);
static rp_int_t rp_http_upstream_process_trailers(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_send_response(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_upgrade(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_upgraded_read_downstream(rp_http_request_t *r);
static void rp_http_upstream_upgraded_write_downstream(rp_http_request_t *r);
static void rp_http_upstream_upgraded_read_upstream(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_upgraded_write_upstream(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_process_upgraded(rp_http_request_t *r,
    rp_uint_t from_upstream, rp_uint_t do_write);
static void
    rp_http_upstream_process_non_buffered_downstream(rp_http_request_t *r);
static void
    rp_http_upstream_process_non_buffered_upstream(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void
    rp_http_upstream_process_non_buffered_request(rp_http_request_t *r,
    rp_uint_t do_write);
static rp_int_t rp_http_upstream_non_buffered_filter_init(void *data);
static rp_int_t rp_http_upstream_non_buffered_filter(void *data,
    ssize_t bytes);
#if (RP_THREADS)
static rp_int_t rp_http_upstream_thread_handler(rp_thread_task_t *task,
    rp_file_t *file);
static void rp_http_upstream_thread_event_handler(rp_event_t *ev);
#endif
static rp_int_t rp_http_upstream_output_filter(void *data,
    rp_chain_t *chain);
static void rp_http_upstream_process_downstream(rp_http_request_t *r);
static void rp_http_upstream_process_upstream(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_process_request(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_store(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_dummy_handler(rp_http_request_t *r,
    rp_http_upstream_t *u);
static void rp_http_upstream_next(rp_http_request_t *r,
    rp_http_upstream_t *u, rp_uint_t ft_type);
static void rp_http_upstream_cleanup(void *data);
static void rp_http_upstream_finalize_request(rp_http_request_t *r,
    rp_http_upstream_t *u, rp_int_t rc);

static rp_int_t rp_http_upstream_process_header_line(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_content_length(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_last_modified(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_set_cookie(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t
    rp_http_upstream_process_cache_control(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_ignore_header_line(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_expires(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_accel_expires(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_limit_rate(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_buffering(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_charset(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_connection(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t
    rp_http_upstream_process_transfer_encoding(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_process_vary(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_copy_header_line(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t
    rp_http_upstream_copy_multi_header_lines(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_copy_content_type(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_copy_last_modified(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_rewrite_location(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_rewrite_refresh(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_rewrite_set_cookie(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
static rp_int_t rp_http_upstream_copy_allow_ranges(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);

#if (RP_HTTP_GZIP)
static rp_int_t rp_http_upstream_copy_content_encoding(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset);
#endif

static rp_int_t rp_http_upstream_add_variables(rp_conf_t *cf);
static rp_int_t rp_http_upstream_addr_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_upstream_status_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_upstream_response_time_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_upstream_response_length_variable(
    rp_http_request_t *r, rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_upstream_header_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_upstream_trailer_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_upstream_cookie_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);

static char *rp_http_upstream(rp_conf_t *cf, rp_command_t *cmd, void *dummy);
static char *rp_http_upstream_server(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);

static rp_int_t rp_http_upstream_set_local(rp_http_request_t *r,
  rp_http_upstream_t *u, rp_http_upstream_local_t *local);

static void *rp_http_upstream_create_main_conf(rp_conf_t *cf);
static char *rp_http_upstream_init_main_conf(rp_conf_t *cf, void *conf);

#if (RP_HTTP_SSL)
static void rp_http_upstream_ssl_init_connection(rp_http_request_t *,
    rp_http_upstream_t *u, rp_connection_t *c);
static void rp_http_upstream_ssl_handshake_handler(rp_connection_t *c);
static void rp_http_upstream_ssl_handshake(rp_http_request_t *,
    rp_http_upstream_t *u, rp_connection_t *c);
static void rp_http_upstream_ssl_save_session(rp_connection_t *c);
static rp_int_t rp_http_upstream_ssl_name(rp_http_request_t *r,
    rp_http_upstream_t *u, rp_connection_t *c);
#endif


static rp_http_upstream_header_t  rp_http_upstream_headers_in[] = {

    { rp_string("Status"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, status),
                 rp_http_upstream_copy_header_line, 0, 0 },

    { rp_string("Content-Type"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, content_type),
                 rp_http_upstream_copy_content_type, 0, 1 },

    { rp_string("Content-Length"),
                 rp_http_upstream_process_content_length, 0,
                 rp_http_upstream_ignore_header_line, 0, 0 },

    { rp_string("Date"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, date),
                 rp_http_upstream_copy_header_line,
                 offsetof(rp_http_headers_out_t, date), 0 },

    { rp_string("Last-Modified"),
                 rp_http_upstream_process_last_modified, 0,
                 rp_http_upstream_copy_last_modified, 0, 0 },

    { rp_string("ETag"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, etag),
                 rp_http_upstream_copy_header_line,
                 offsetof(rp_http_headers_out_t, etag), 0 },

    { rp_string("Server"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, server),
                 rp_http_upstream_copy_header_line,
                 offsetof(rp_http_headers_out_t, server), 0 },

    { rp_string("WWW-Authenticate"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, www_authenticate),
                 rp_http_upstream_copy_header_line, 0, 0 },

    { rp_string("Location"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, location),
                 rp_http_upstream_rewrite_location, 0, 0 },

    { rp_string("Refresh"),
                 rp_http_upstream_ignore_header_line, 0,
                 rp_http_upstream_rewrite_refresh, 0, 0 },

    { rp_string("Set-Cookie"),
                 rp_http_upstream_process_set_cookie,
                 offsetof(rp_http_upstream_headers_in_t, cookies),
                 rp_http_upstream_rewrite_set_cookie, 0, 1 },

    { rp_string("Content-Disposition"),
                 rp_http_upstream_ignore_header_line, 0,
                 rp_http_upstream_copy_header_line, 0, 1 },

    { rp_string("Cache-Control"),
                 rp_http_upstream_process_cache_control, 0,
                 rp_http_upstream_copy_multi_header_lines,
                 offsetof(rp_http_headers_out_t, cache_control), 1 },

    { rp_string("Expires"),
                 rp_http_upstream_process_expires, 0,
                 rp_http_upstream_copy_header_line,
                 offsetof(rp_http_headers_out_t, expires), 1 },

    { rp_string("Accept-Ranges"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, accept_ranges),
                 rp_http_upstream_copy_allow_ranges,
                 offsetof(rp_http_headers_out_t, accept_ranges), 1 },

    { rp_string("Content-Range"),
                 rp_http_upstream_ignore_header_line, 0,
                 rp_http_upstream_copy_header_line,
                 offsetof(rp_http_headers_out_t, content_range), 0 },

    { rp_string("Connection"),
                 rp_http_upstream_process_connection, 0,
                 rp_http_upstream_ignore_header_line, 0, 0 },

    { rp_string("Keep-Alive"),
                 rp_http_upstream_ignore_header_line, 0,
                 rp_http_upstream_ignore_header_line, 0, 0 },

    { rp_string("Vary"),
                 rp_http_upstream_process_vary, 0,
                 rp_http_upstream_copy_header_line, 0, 0 },

    { rp_string("Link"),
                 rp_http_upstream_ignore_header_line, 0,
                 rp_http_upstream_copy_multi_header_lines,
                 offsetof(rp_http_headers_out_t, link), 0 },

    { rp_string("X-Accel-Expires"),
                 rp_http_upstream_process_accel_expires, 0,
                 rp_http_upstream_copy_header_line, 0, 0 },

    { rp_string("X-Accel-Redirect"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, x_accel_redirect),
                 rp_http_upstream_copy_header_line, 0, 0 },

    { rp_string("X-Accel-Limit-Rate"),
                 rp_http_upstream_process_limit_rate, 0,
                 rp_http_upstream_copy_header_line, 0, 0 },

    { rp_string("X-Accel-Buffering"),
                 rp_http_upstream_process_buffering, 0,
                 rp_http_upstream_copy_header_line, 0, 0 },

    { rp_string("X-Accel-Charset"),
                 rp_http_upstream_process_charset, 0,
                 rp_http_upstream_copy_header_line, 0, 0 },

    { rp_string("Transfer-Encoding"),
                 rp_http_upstream_process_transfer_encoding, 0,
                 rp_http_upstream_ignore_header_line, 0, 0 },

#if (RP_HTTP_GZIP)
    { rp_string("Content-Encoding"),
                 rp_http_upstream_process_header_line,
                 offsetof(rp_http_upstream_headers_in_t, content_encoding),
                 rp_http_upstream_copy_content_encoding, 0, 0 },
#endif

    { rp_null_string, NULL, 0, NULL, 0, 0 }
};


static rp_command_t  rp_http_upstream_commands[] = {

    { rp_string("upstream"),
      RP_HTTP_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_TAKE1,
      rp_http_upstream,
      0,
      0,
      NULL },

    { rp_string("server"),
      RP_HTTP_UPS_CONF|RP_CONF_1MORE,
      rp_http_upstream_server,
      RP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_upstream_module_ctx = {
    rp_http_upstream_add_variables,       /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rp_http_upstream_create_main_conf,    /* create main configuration */
    rp_http_upstream_init_main_conf,      /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_upstream_module = {
    RP_MODULE_V1,
    &rp_http_upstream_module_ctx,         /* module context */
    rp_http_upstream_commands,            /* module directives */
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


static rp_http_variable_t  rp_http_upstream_vars[] = {

    { rp_string("upstream_addr"), NULL,
      rp_http_upstream_addr_variable, 0,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_status"), NULL,
      rp_http_upstream_status_variable, 0,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_connect_time"), NULL,
      rp_http_upstream_response_time_variable, 2,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_header_time"), NULL,
      rp_http_upstream_response_time_variable, 1,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_response_time"), NULL,
      rp_http_upstream_response_time_variable, 0,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_response_length"), NULL,
      rp_http_upstream_response_length_variable, 0,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_bytes_received"), NULL,
      rp_http_upstream_response_length_variable, 1,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_bytes_sent"), NULL,
      rp_http_upstream_response_length_variable, 2,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

#if (RP_HTTP_CACHE)

    { rp_string("upstream_cache_status"), NULL,
      rp_http_upstream_cache_status, 0,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_cache_last_modified"), NULL,
      rp_http_upstream_cache_last_modified, 0,
      RP_HTTP_VAR_NOCACHEABLE|RP_HTTP_VAR_NOHASH, 0 },

    { rp_string("upstream_cache_etag"), NULL,
      rp_http_upstream_cache_etag, 0,
      RP_HTTP_VAR_NOCACHEABLE|RP_HTTP_VAR_NOHASH, 0 },

#endif

    { rp_string("upstream_http_"), NULL, rp_http_upstream_header_variable,
      0, RP_HTTP_VAR_NOCACHEABLE|RP_HTTP_VAR_PREFIX, 0 },

    { rp_string("upstream_trailer_"), NULL, rp_http_upstream_trailer_variable,
      0, RP_HTTP_VAR_NOCACHEABLE|RP_HTTP_VAR_PREFIX, 0 },

    { rp_string("upstream_cookie_"), NULL, rp_http_upstream_cookie_variable,
      0, RP_HTTP_VAR_NOCACHEABLE|RP_HTTP_VAR_PREFIX, 0 },

      rp_http_null_variable
};


static rp_http_upstream_next_t  rp_http_upstream_next_errors[] = {
    { 500, RP_HTTP_UPSTREAM_FT_HTTP_500 },
    { 502, RP_HTTP_UPSTREAM_FT_HTTP_502 },
    { 503, RP_HTTP_UPSTREAM_FT_HTTP_503 },
    { 504, RP_HTTP_UPSTREAM_FT_HTTP_504 },
    { 403, RP_HTTP_UPSTREAM_FT_HTTP_403 },
    { 404, RP_HTTP_UPSTREAM_FT_HTTP_404 },
    { 429, RP_HTTP_UPSTREAM_FT_HTTP_429 },
    { 0, 0 }
};


rp_conf_bitmask_t  rp_http_upstream_cache_method_mask[] = {
    { rp_string("GET"), RP_HTTP_GET },
    { rp_string("HEAD"), RP_HTTP_HEAD },
    { rp_string("POST"), RP_HTTP_POST },
    { rp_null_string, 0 }
};


rp_conf_bitmask_t  rp_http_upstream_ignore_headers_masks[] = {
    { rp_string("X-Accel-Redirect"), RP_HTTP_UPSTREAM_IGN_XA_REDIRECT },
    { rp_string("X-Accel-Expires"), RP_HTTP_UPSTREAM_IGN_XA_EXPIRES },
    { rp_string("X-Accel-Limit-Rate"), RP_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE },
    { rp_string("X-Accel-Buffering"), RP_HTTP_UPSTREAM_IGN_XA_BUFFERING },
    { rp_string("X-Accel-Charset"), RP_HTTP_UPSTREAM_IGN_XA_CHARSET },
    { rp_string("Expires"), RP_HTTP_UPSTREAM_IGN_EXPIRES },
    { rp_string("Cache-Control"), RP_HTTP_UPSTREAM_IGN_CACHE_CONTROL },
    { rp_string("Set-Cookie"), RP_HTTP_UPSTREAM_IGN_SET_COOKIE },
    { rp_string("Vary"), RP_HTTP_UPSTREAM_IGN_VARY },
    { rp_null_string, 0 }
};


rp_int_t
rp_http_upstream_create(rp_http_request_t *r)
{
    rp_http_upstream_t  *u;

    u = r->upstream;

    if (u && u->cleanup) {
        r->main->count++;
        rp_http_upstream_cleanup(r);
    }

    u = rp_pcalloc(r->pool, sizeof(rp_http_upstream_t));
    if (u == NULL) {
        return RP_ERROR;
    }

    r->upstream = u;

    u->peer.log = r->connection->log;
    u->peer.log_error = RP_ERROR_ERR;

#if (RP_HTTP_CACHE)
    r->cache = NULL;
#endif

    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    return RP_OK;
}


void
rp_http_upstream_init(rp_http_request_t *r)
{
    rp_connection_t     *c;

    c = r->connection;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http init upstream, client timer: %d", c->read->timer_set);

#if (RP_HTTP_V2)
    if (r->stream) {
        rp_http_upstream_init_request(r);
        return;
    }
#endif

    if (c->read->timer_set) {
        rp_del_timer(c->read);
    }

    if (rp_event_flags & RP_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (rp_add_event(c->write, RP_WRITE_EVENT, RP_CLEAR_EVENT)
                == RP_ERROR)
            {
                rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    rp_http_upstream_init_request(r);
}


static void
rp_http_upstream_init_request(rp_http_request_t *r)
{
    rp_str_t                      *host;
    rp_uint_t                      i;
    rp_resolver_ctx_t             *ctx, temp;
    rp_http_cleanup_t             *cln;
    rp_http_upstream_t            *u;
    rp_http_core_loc_conf_t       *clcf;
    rp_http_upstream_srv_conf_t   *uscf, **uscfp;
    rp_http_upstream_main_conf_t  *umcf;

    if (r->aio) {
        return;
    }

    u = r->upstream;

#if (RP_HTTP_CACHE)

    if (u->conf->cache) {
        rp_int_t  rc;

        rc = rp_http_upstream_cache(r, u);

        if (rc == RP_BUSY) {
            r->write_event_handler = rp_http_upstream_init_request;
            return;
        }

        r->write_event_handler = rp_http_request_empty_handler;

        if (rc == RP_ERROR) {
            rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rc == RP_OK) {
            rc = rp_http_upstream_cache_send(r, u);

            if (rc == RP_DONE) {
                return;
            }

            if (rc == RP_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = RP_DECLINED;
                r->cached = 0;
                u->buffer.start = NULL;
                u->cache_status = RP_HTTP_CACHE_MISS;
                u->request_sent = 1;
            }
        }

        if (rc != RP_DECLINED) {
            rp_http_finalize_request(r, rc);
            return;
        }
    }

#endif

    u->store = u->conf->store;

    if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
        r->read_event_handler = rp_http_upstream_rd_check_broken_connection;
        r->write_event_handler = rp_http_upstream_wr_check_broken_connection;
    }

    if (r->request_body) {
        u->request_bufs = r->request_body->bufs;
    }

    if (u->create_request(r) != RP_OK) {
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rp_http_upstream_set_local(r, u, u->conf->local) != RP_OK) {
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->conf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    u->output.alignment = clcf->directio_alignment;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;

    if (u->output.output_filter == NULL) {
        u->output.output_filter = rp_chain_writer;
        u->output.filter_ctx = &u->writer;
    }

    u->writer.pool = r->pool;

    if (r->upstream_states == NULL) {

        r->upstream_states = rp_array_create(r->pool, 1,
                                            sizeof(rp_http_upstream_state_t));
        if (r->upstream_states == NULL) {
            rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {

        u->state = rp_array_push(r->upstream_states);
        if (u->state == NULL) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        rp_memzero(u->state, sizeof(rp_http_upstream_state_t));
    }

    cln = rp_http_cleanup_add(r, 0);
    if (cln == NULL) {
        rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = rp_http_upstream_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;

    if (u->resolved == NULL) {

        uscf = u->conf->upstream;

    } else {

#if (RP_HTTP_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = rp_http_get_module_main_conf(r, rp_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && rp_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "no port in upstream \"%V\"", host);
                rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (rp_http_upstream_create_round_robin_peer(r, u->resolved)
                != RP_OK)
            {
                rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            rp_http_upstream_connect(r, u);

            return;
        }

        if (u->resolved->port == 0) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "no port in upstream \"%V\"", host);
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        ctx = rp_resolve_start(clcf->resolver, &temp);
        if (ctx == NULL) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == RP_NO_RESOLVER) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "no resolver defined to resolve %V", host);

            rp_http_upstream_finalize_request(r, u, RP_HTTP_BAD_GATEWAY);
            return;
        }

        ctx->name = *host;
        ctx->handler = rp_http_upstream_resolve_handler;
        ctx->data = r;
        ctx->timeout = clcf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (rp_resolve_name(ctx) != RP_OK) {
            u->resolved->ctx = NULL;
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "no upstream configuration");
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (RP_HTTP_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(r, uscf) != RP_OK) {
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = rp_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    rp_http_upstream_connect(r, u);
}


#if (RP_HTTP_CACHE)

static rp_int_t
rp_http_upstream_cache(rp_http_request_t *r, rp_http_upstream_t *u)
{
    rp_int_t               rc;
    rp_http_cache_t       *c;
    rp_http_file_cache_t  *cache;

    c = r->cache;

    if (c == NULL) {

        if (!(r->method & u->conf->cache_methods)) {
            return RP_DECLINED;
        }

        rc = rp_http_upstream_cache_get(r, u, &cache);

        if (rc != RP_OK) {
            return rc;
        }

        if (r->method == RP_HTTP_HEAD && u->conf->cache_convert_head) {
            u->method = rp_http_core_get_method;
        }

        if (rp_http_file_cache_new(r) != RP_OK) {
            return RP_ERROR;
        }

        if (u->create_key(r) != RP_OK) {
            return RP_ERROR;
        }

        /* TODO: add keys */

        rp_http_file_cache_create_key(r);

        if (r->cache->header_start + 256 > u->conf->buffer_size) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "%V_buffer_size %uz is not enough for cache key, "
                          "it should be increased to at least %uz",
                          &u->conf->module, u->conf->buffer_size,
                          rp_align(r->cache->header_start + 256, 1024));

            r->cache = NULL;
            return RP_DECLINED;
        }

        u->cacheable = 1;

        c = r->cache;

        c->body_start = u->conf->buffer_size;
        c->min_uses = u->conf->cache_min_uses;
        c->file_cache = cache;

        switch (rp_http_test_predicates(r, u->conf->cache_bypass)) {

        case RP_ERROR:
            return RP_ERROR;

        case RP_DECLINED:
            u->cache_status = RP_HTTP_CACHE_BYPASS;
            return RP_DECLINED;

        default: /* RP_OK */
            break;
        }

        c->lock = u->conf->cache_lock;
        c->lock_timeout = u->conf->cache_lock_timeout;
        c->lock_age = u->conf->cache_lock_age;

        u->cache_status = RP_HTTP_CACHE_MISS;
    }

    rc = rp_http_file_cache_open(r);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream cache: %i", rc);

    switch (rc) {

    case RP_HTTP_CACHE_STALE:

        if (((u->conf->cache_use_stale & RP_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background
            && u->conf->cache_background_update)
        {
            if (rp_http_upstream_cache_background_update(r, u) == RP_OK) {
                r->cache->background = 1;
                u->cache_status = rc;
                rc = RP_OK;

            } else {
                rc = RP_ERROR;
            }
        }

        break;

    case RP_HTTP_CACHE_UPDATING:

        if (((u->conf->cache_use_stale & RP_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background)
        {
            u->cache_status = rc;
            rc = RP_OK;

        } else {
            rc = RP_HTTP_CACHE_STALE;
        }

        break;

    case RP_OK:
        u->cache_status = RP_HTTP_CACHE_HIT;
    }

    switch (rc) {

    case RP_OK:

        return RP_OK;

    case RP_HTTP_CACHE_STALE:

        c->valid_sec = 0;
        c->updating_sec = 0;
        c->error_sec = 0;

        u->buffer.start = NULL;
        u->cache_status = RP_HTTP_CACHE_EXPIRED;

        break;

    case RP_DECLINED:

        if ((size_t) (u->buffer.end - u->buffer.start) < u->conf->buffer_size) {
            u->buffer.start = NULL;

        } else {
            u->buffer.pos = u->buffer.start + c->header_start;
            u->buffer.last = u->buffer.pos;
        }

        break;

    case RP_HTTP_CACHE_SCARCE:

        u->cacheable = 0;

        break;

    case RP_AGAIN:

        return RP_BUSY;

    case RP_ERROR:

        return RP_ERROR;

    default:

        /* cached RP_HTTP_BAD_GATEWAY, RP_HTTP_GATEWAY_TIME_OUT, etc. */

        u->cache_status = RP_HTTP_CACHE_HIT;

        return rc;
    }

    if (rp_http_upstream_cache_check_range(r, u) == RP_DECLINED) {
        u->cacheable = 0;
    }

    r->cached = 0;

    return RP_DECLINED;
}


static rp_int_t
rp_http_upstream_cache_get(rp_http_request_t *r, rp_http_upstream_t *u,
    rp_http_file_cache_t **cache)
{
    rp_str_t               *name, val;
    rp_uint_t               i;
    rp_http_file_cache_t  **caches;

    if (u->conf->cache_zone) {
        *cache = u->conf->cache_zone->data;
        return RP_OK;
    }

    if (rp_http_complex_value(r, u->conf->cache_value, &val) != RP_OK) {
        return RP_ERROR;
    }

    if (val.len == 0
        || (val.len == 3 && rp_strncmp(val.data, "off", 3) == 0))
    {
        return RP_DECLINED;
    }

    caches = u->caches->elts;

    for (i = 0; i < u->caches->nelts; i++) {
        name = &caches[i]->shm_zone->shm.name;

        if (name->len == val.len
            && rp_strncmp(name->data, val.data, val.len) == 0)
        {
            *cache = caches[i];
            return RP_OK;
        }
    }

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "cache \"%V\" not found", &val);

    return RP_ERROR;
}


static rp_int_t
rp_http_upstream_cache_send(rp_http_request_t *r, rp_http_upstream_t *u)
{
    rp_int_t          rc;
    rp_http_cache_t  *c;

    r->cached = 1;
    c = r->cache;

    if (c->header_start == c->body_start) {
        r->http_version = RP_HTTP_VERSION_9;
        return rp_http_cache_send(r);
    }

    /* TODO: cache stack */

    u->buffer = *c->buf;
    u->buffer.pos += c->header_start;

    rp_memzero(&u->headers_in, sizeof(rp_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (rp_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(rp_table_elt_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(rp_table_elt_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    rc = u->process_header(r);

    if (rc == RP_OK) {

        if (rp_http_upstream_process_headers(r, u) != RP_OK) {
            return RP_DONE;
        }

        return rp_http_cache_send(r);
    }

    if (rc == RP_ERROR) {
        return RP_ERROR;
    }

    if (rc == RP_AGAIN) {
        rc = RP_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* rc == RP_HTTP_UPSTREAM_INVALID_HEADER */

    rp_log_error(RP_LOG_CRIT, r->connection->log, 0,
                  "cache file \"%s\" contains invalid header",
                  c->file.name.data);

    /* TODO: delete file */

    return rc;
}


static rp_int_t
rp_http_upstream_cache_background_update(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    rp_http_request_t  *sr;

    if (r == r->main) {
        r->preserve_body = 1;
    }

    if (rp_http_subrequest(r, &r->uri, &r->args, &sr, NULL,
                            RP_HTTP_SUBREQUEST_CLONE
                            |RP_HTTP_SUBREQUEST_BACKGROUND)
        != RP_OK)
    {
        return RP_ERROR;
    }

    sr->header_only = 1;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_cache_check_range(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    off_t             offset;
    u_char           *p, *start;
    rp_table_elt_t  *h;

    h = r->headers_in.range;

    if (h == NULL
        || !u->cacheable
        || u->conf->cache_max_range_offset == RP_MAX_OFF_T_VALUE)
    {
        return RP_OK;
    }

    if (u->conf->cache_max_range_offset == 0) {
        return RP_DECLINED;
    }

    if (h->value.len < 7
        || rp_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return RP_OK;
    }

    p = h->value.data + 6;

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return RP_DECLINED;
    }

    start = p;

    while (*p >= '0' && *p <= '9') { p++; }

    offset = rp_atoof(start, p - start);

    if (offset >= u->conf->cache_max_range_offset) {
        return RP_DECLINED;
    }

    return RP_OK;
}

#endif


static void
rp_http_upstream_resolve_handler(rp_resolver_ctx_t *ctx)
{
    rp_uint_t                     run_posted;
    rp_connection_t              *c;
    rp_http_request_t            *r;
    rp_http_upstream_t           *u;
    rp_http_upstream_resolved_t  *ur;

    run_posted = ctx->async;

    r = ctx->data;
    c = r->connection;

    u = r->upstream;
    ur = u->resolved;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream resolve: \"%V?%V\"", &r->uri, &r->args);

    if (ctx->state) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      rp_resolver_strerror(ctx->state));

        rp_http_upstream_finalize_request(r, u, RP_HTTP_BAD_GATEWAY);
        goto failed;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (RP_DEBUG)
    {
    u_char      text[RP_SOCKADDR_STRLEN];
    rp_str_t   addr;
    rp_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = rp_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, RP_SOCKADDR_STRLEN, 0);

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (rp_http_upstream_create_round_robin_peer(r, ur) != RP_OK) {
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_INTERNAL_SERVER_ERROR);
        goto failed;
    }

    rp_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = rp_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    rp_http_upstream_connect(r, u);

failed:

    if (run_posted) {
        rp_http_run_posted_requests(c);
    }
}


static void
rp_http_upstream_handler(rp_event_t *ev)
{
    rp_connection_t     *c;
    rp_http_request_t   *r;
    rp_http_upstream_t  *u;

    c = ev->data;
    r = c->data;

    u = r->upstream;
    c = r->connection;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream request: \"%V?%V\"", &r->uri, &r->args);

    if (ev->delayed && ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
    }

    if (ev->write) {
        u->write_event_handler(r, u);

    } else {
        u->read_event_handler(r, u);
    }

    rp_http_run_posted_requests(c);
}


static void
rp_http_upstream_rd_check_broken_connection(rp_http_request_t *r)
{
    rp_http_upstream_check_broken_connection(r, r->connection->read);
}


static void
rp_http_upstream_wr_check_broken_connection(rp_http_request_t *r)
{
    rp_http_upstream_check_broken_connection(r, r->connection->write);
}


static void
rp_http_upstream_check_broken_connection(rp_http_request_t *r,
    rp_event_t *ev)
{
    int                  n;
    char                 buf[1];
    rp_err_t            err;
    rp_int_t            event;
    rp_connection_t     *c;
    rp_http_upstream_t  *u;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, ev->log, 0,
                   "http upstream check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;
    u = r->upstream;

    if (c->error) {
        if ((rp_event_flags & RP_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? RP_WRITE_EVENT : RP_READ_EVENT;

            if (rp_del_event(ev, event, 0) != RP_OK) {
                rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        if (!u->cacheable) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#if (RP_HTTP_V2)
    if (r->stream) {
        return;
    }
#endif

#if (RP_HAVE_KQUEUE)

    if (rp_event_flags & RP_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            rp_log_error(RP_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client prematurely closed "
                          "connection, so upstream connection is closed too");
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        rp_log_error(RP_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

#if (RP_HAVE_EPOLLRDHUP)

    if ((rp_event_flags & RP_USE_EPOLL_EVENT) && rp_use_epoll_rdhup) {
        socklen_t  len;

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(rp_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = rp_socket_errno;
        }

        if (err) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            rp_log_error(RP_LOG_INFO, ev->log, err,
                        "epoll_wait() reported that client prematurely closed "
                        "connection, so upstream connection is closed too");
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        rp_log_error(RP_LOG_INFO, ev->log, err,
                      "epoll_wait() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = rp_socket_errno;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, ev->log, err,
                   "http upstream recv(): %d", n);

    if (ev->write && (n >= 0 || err == RP_EAGAIN)) {
        return;
    }

    if ((rp_event_flags & RP_USE_LEVEL_EVENT) && ev->active) {

        event = ev->write ? RP_WRITE_EVENT : RP_READ_EVENT;

        if (rp_del_event(ev, event, 0) != RP_OK) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == RP_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (!u->cacheable && u->peer.connection) {
        rp_log_error(RP_LOG_INFO, ev->log, err,
                      "client prematurely closed connection, "
                      "so upstream connection is closed too");
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    rp_log_error(RP_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    if (u->peer.connection == NULL) {
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_CLIENT_CLOSED_REQUEST);
    }
}


static void
rp_http_upstream_connect(rp_http_request_t *r, rp_http_upstream_t *u)
{
    rp_int_t          rc;
    rp_connection_t  *c;

    r->connection->log->action = "connecting to upstream";

    if (u->state && u->state->response_time == (rp_msec_t) -1) {
        u->state->response_time = rp_current_msec - u->start_time;
    }

    u->state = rp_array_push(r->upstream_states);
    if (u->state == NULL) {
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rp_memzero(u->state, sizeof(rp_http_upstream_state_t));

    u->start_time = rp_current_msec;

    u->state->response_time = (rp_msec_t) -1;
    u->state->connect_time = (rp_msec_t) -1;
    u->state->header_time = (rp_msec_t) -1;

    rc = rp_event_connect_peer(&u->peer);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream connect: %i", rc);

    if (rc == RP_ERROR) {
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == RP_BUSY) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0, "no live upstreams");
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_NOLIVE);
        return;
    }

    if (rc == RP_DECLINED) {
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    /* rc == RP_OK || rc == RP_AGAIN || rc == RP_DONE */

    c = u->peer.connection;

    c->requests++;

    c->data = r;

    c->write->handler = rp_http_upstream_handler;
    c->read->handler = rp_http_upstream_handler;

    u->write_event_handler = rp_http_upstream_send_request_handler;
    u->read_event_handler = rp_http_upstream_process_header;

    c->sendfile &= r->connection->sendfile;
    u->output.sendfile = c->sendfile;

    if (r->connection->tcp_nopush == RP_TCP_NOPUSH_DISABLED) {
        c->tcp_nopush = RP_TCP_NOPUSH_DISABLED;
    }

    if (c->pool == NULL) {

        /* we need separate pool here to be able to cache SSL connections */

        c->pool = rp_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    /* init or reinit the rp_output_chain() and rp_chain_writer() contexts */

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit = 0;

    if (u->request_sent) {
        if (rp_http_upstream_reinit(r, u) != RP_OK) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (r->request_body
        && r->request_body->buf
        && r->request_body->temp_file
        && r == r->main)
    {
        /*
         * the r->request_body->buf can be reused for one request only,
         * the subrequests should allocate their own temporary bufs
         */

        u->output.free = rp_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->output.free->buf = r->request_body->buf;
        u->output.free->next = NULL;
        u->output.allocated = 1;

        r->request_body->buf->pos = r->request_body->buf->start;
        r->request_body->buf->last = r->request_body->buf->start;
        r->request_body->buf->tag = u->output.tag;
    }

    u->request_sent = 0;
    u->request_body_sent = 0;
    u->request_body_blocked = 0;

    if (rc == RP_AGAIN) {
        rp_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

#if (RP_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        rp_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    rp_http_upstream_send_request(r, u, 1);
}


#if (RP_HTTP_SSL)

static void
rp_http_upstream_ssl_init_connection(rp_http_request_t *r,
    rp_http_upstream_t *u, rp_connection_t *c)
{
    rp_int_t                  rc;
    rp_http_core_loc_conf_t  *clcf;

    if (rp_http_upstream_test_connect(c) != RP_OK) {
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (rp_ssl_create_connection(u->conf->ssl, c,
                                  RP_SSL_BUFFER|RP_SSL_CLIENT)
        != RP_OK)
    {
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    c->sendfile = 0;
    u->output.sendfile = 0;

    if (u->conf->ssl_server_name || u->conf->ssl_verify) {
        if (rp_http_upstream_ssl_name(r, u, c) != RP_OK) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->conf->ssl_session_reuse) {
        c->ssl->save_session = rp_http_upstream_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != RP_OK) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        /* abbreviated SSL handshake may interact badly with Nagle */

        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

        if (clcf->tcp_nodelay && rp_tcp_nodelay(c) != RP_OK) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    r->connection->log->action = "SSL handshaking to upstream";

    rc = rp_ssl_handshake(c);

    if (rc == RP_AGAIN) {

        if (!c->write->timer_set) {
            rp_add_timer(c->write, u->conf->connect_timeout);
        }

        c->ssl->handler = rp_http_upstream_ssl_handshake_handler;
        return;
    }

    rp_http_upstream_ssl_handshake(r, u, c);
}


static void
rp_http_upstream_ssl_handshake_handler(rp_connection_t *c)
{
    rp_http_request_t   *r;
    rp_http_upstream_t  *u;

    r = c->data;

    u = r->upstream;
    c = r->connection;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl handshake: \"%V?%V\"",
                   &r->uri, &r->args);

    rp_http_upstream_ssl_handshake(r, u, u->peer.connection);

    rp_http_run_posted_requests(c);
}


static void
rp_http_upstream_ssl_handshake(rp_http_request_t *r, rp_http_upstream_t *u,
    rp_connection_t *c)
{
    long  rc;

    if (c->ssl->handshaked) {

        if (u->conf->ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK) {
                rp_log_error(RP_LOG_ERR, c->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            if (rp_ssl_check_host(c, &u->ssl_name) != RP_OK) {
                rp_log_error(RP_LOG_ERR, c->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        c->write->handler = rp_http_upstream_handler;
        c->read->handler = rp_http_upstream_handler;

        rp_http_upstream_send_request(r, u, 1);

        return;
    }

    if (c->write->timedout) {
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

failed:

    rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_ERROR);
}


static void
rp_http_upstream_ssl_save_session(rp_connection_t *c)
{
    rp_http_request_t   *r;
    rp_http_upstream_t  *u;

    if (c->idle) {
        return;
    }

    r = c->data;

    u = r->upstream;
    c = r->connection;

    rp_http_set_log_request(c->log, r);

    u->peer.save_session(&u->peer, u->peer.data);
}


static rp_int_t
rp_http_upstream_ssl_name(rp_http_request_t *r, rp_http_upstream_t *u,
    rp_connection_t *c)
{
    u_char     *p, *last;
    rp_str_t   name;

    if (u->conf->ssl_name) {
        if (rp_http_complex_value(r, u->conf->ssl_name, &name) != RP_OK) {
            return RP_ERROR;
        }

    } else {
        name = u->ssl_name;
    }

    if (name.len == 0) {
        goto done;
    }

    /*
     * ssl name here may contain port, notably if derived from $proxy_host
     * or $http_host; we have to strip it
     */

    p = name.data;
    last = name.data + name.len;

    if (*p == '[') {
        p = rp_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = rp_strlchr(p, last, ':');

    if (p != NULL) {
        name.len = p - name.data;
    }

    if (!u->conf->ssl_server_name) {
        goto done;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    /* as per RFC 6066, literal IPv4 and IPv6 addresses are not permitted */

    if (name.len == 0 || *name.data == '[') {
        goto done;
    }

    if (rp_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = rp_pnalloc(r->pool, name.len + 1);
    if (p == NULL) {
        return RP_ERROR;
    }

    (void) rp_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(c->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        rp_ssl_error(RP_LOG_ERR, r->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return RP_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return RP_OK;
}

#endif


static rp_int_t
rp_http_upstream_reinit(rp_http_request_t *r, rp_http_upstream_t *u)
{
    off_t         file_pos;
    rp_chain_t  *cl;

    if (u->reinit_request(r) != RP_OK) {
        return RP_ERROR;
    }

    u->keepalive = 0;
    u->upgrade = 0;

    rp_memzero(&u->headers_in, sizeof(rp_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (rp_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(rp_table_elt_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(rp_table_elt_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    /* reinit the request chain */

    file_pos = 0;

    for (cl = u->request_bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->start;

        /* there is at most one file */

        if (cl->buf->in_file) {
            cl->buf->file_pos = file_pos;
            file_pos = cl->buf->file_last;
        }
    }

    /* reinit the subrequest's rp_output_chain() context */

    if (r->request_body && r->request_body->temp_file
        && r != r->main && u->output.buf)
    {
        u->output.free = rp_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            return RP_ERROR;
        }

        u->output.free->buf = u->output.buf;
        u->output.free->next = NULL;

        u->output.buf->pos = u->output.buf->start;
        u->output.buf->last = u->output.buf->start;
    }

    u->output.buf = NULL;
    u->output.in = NULL;
    u->output.busy = NULL;

    /* reinit u->buffer */

    u->buffer.pos = u->buffer.start;

#if (RP_HTTP_CACHE)

    if (r->cache) {
        u->buffer.pos += r->cache->header_start;
    }

#endif

    u->buffer.last = u->buffer.pos;

    return RP_OK;
}


static void
rp_http_upstream_send_request(rp_http_request_t *r, rp_http_upstream_t *u,
    rp_uint_t do_write)
{
    rp_int_t          rc;
    rp_connection_t  *c;

    c = u->peer.connection;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream send request");

    if (u->state->connect_time == (rp_msec_t) -1) {
        u->state->connect_time = rp_current_msec - u->start_time;
    }

    if (!u->request_sent && rp_http_upstream_test_connect(c) != RP_OK) {
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    c->log->action = "sending request to upstream";

    rc = rp_http_upstream_send_request_body(r, u, do_write);

    if (rc == RP_ERROR) {
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (rc >= RP_HTTP_SPECIAL_RESPONSE) {
        rp_http_upstream_finalize_request(r, u, rc);
        return;
    }

    if (rc == RP_AGAIN) {
        if (!c->write->ready || u->request_body_blocked) {
            rp_add_timer(c->write, u->conf->send_timeout);

        } else if (c->write->timer_set) {
            rp_del_timer(c->write);
        }

        if (rp_handle_write_event(c->write, u->conf->send_lowat) != RP_OK) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (c->write->ready && c->tcp_nopush == RP_TCP_NOPUSH_SET) {
            if (rp_tcp_push(c->fd) == -1) {
                rp_log_error(RP_LOG_CRIT, c->log, rp_socket_errno,
                              rp_tcp_push_n " failed");
                rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            c->tcp_nopush = RP_TCP_NOPUSH_UNSET;
        }

        return;
    }

    /* rc == RP_OK */

    if (c->write->timer_set) {
        rp_del_timer(c->write);
    }

    if (c->tcp_nopush == RP_TCP_NOPUSH_SET) {
        if (rp_tcp_push(c->fd) == -1) {
            rp_log_error(RP_LOG_CRIT, c->log, rp_socket_errno,
                          rp_tcp_push_n " failed");
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        c->tcp_nopush = RP_TCP_NOPUSH_UNSET;
    }

    if (!u->conf->preserve_output) {
        u->write_event_handler = rp_http_upstream_dummy_handler;
    }

    if (rp_handle_write_event(c->write, 0) != RP_OK) {
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!u->request_body_sent) {
        u->request_body_sent = 1;

        if (u->header_sent) {
            return;
        }

        rp_add_timer(c->read, u->conf->read_timeout);

        if (c->read->ready) {
            rp_http_upstream_process_header(r, u);
            return;
        }
    }
}


static rp_int_t
rp_http_upstream_send_request_body(rp_http_request_t *r,
    rp_http_upstream_t *u, rp_uint_t do_write)
{
    rp_int_t                  rc;
    rp_chain_t               *out, *cl, *ln;
    rp_connection_t          *c;
    rp_http_core_loc_conf_t  *clcf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request body");

    if (!r->request_body_no_buffering) {

        /* buffered request body */

        if (!u->request_sent) {
            u->request_sent = 1;
            out = u->request_bufs;

        } else {
            out = NULL;
        }

        rc = rp_output_chain(&u->output, out);

        if (rc == RP_AGAIN) {
            u->request_body_blocked = 1;

        } else {
            u->request_body_blocked = 0;
        }

        return rc;
    }

    if (!u->request_sent) {
        u->request_sent = 1;
        out = u->request_bufs;

        if (r->request_body->bufs) {
            for (cl = out; cl->next; cl = cl->next) { /* void */ }
            cl->next = r->request_body->bufs;
            r->request_body->bufs = NULL;
        }

        c = u->peer.connection;
        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

        if (clcf->tcp_nodelay && rp_tcp_nodelay(c) != RP_OK) {
            return RP_ERROR;
        }

        r->read_event_handler = rp_http_upstream_read_request_handler;

    } else {
        out = NULL;
    }

    for ( ;; ) {

        if (do_write) {
            rc = rp_output_chain(&u->output, out);

            if (rc == RP_ERROR) {
                return RP_ERROR;
            }

            while (out) {
                ln = out;
                out = out->next;
                rp_free_chain(r->pool, ln);
            }

            if (rc == RP_AGAIN) {
                u->request_body_blocked = 1;

            } else {
                u->request_body_blocked = 0;
            }

            if (rc == RP_OK && !r->reading_body) {
                break;
            }
        }

        if (r->reading_body) {
            /* read client request body */

            rc = rp_http_read_unbuffered_request_body(r);

            if (rc >= RP_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            out = r->request_body->bufs;
            r->request_body->bufs = NULL;
        }

        /* stop if there is nothing to send */

        if (out == NULL) {
            rc = RP_AGAIN;
            break;
        }

        do_write = 1;
    }

    if (!r->reading_body) {
        if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
            r->read_event_handler =
                                  rp_http_upstream_rd_check_broken_connection;
        }
    }

    return rc;
}


static void
rp_http_upstream_send_request_handler(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    rp_connection_t  *c;

    c = u->peer.connection;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request handler");

    if (c->write->timedout) {
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

#if (RP_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        rp_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    if (u->header_sent && !u->conf->preserve_output) {
        u->write_event_handler = rp_http_upstream_dummy_handler;

        (void) rp_handle_write_event(c->write, 0);

        return;
    }

    rp_http_upstream_send_request(r, u, 1);
}


static void
rp_http_upstream_read_request_handler(rp_http_request_t *r)
{
    rp_connection_t     *c;
    rp_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream read request handler");

    if (c->read->timedout) {
        c->timedout = 1;
        rp_http_upstream_finalize_request(r, u, RP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rp_http_upstream_send_request(r, u, 0);
}


static void
rp_http_upstream_process_header(rp_http_request_t *r, rp_http_upstream_t *u)
{
    ssize_t            n;
    rp_int_t          rc;
    rp_connection_t  *c;

    c = u->peer.connection;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process header");

    c->log->action = "reading response header from upstream";

    if (c->read->timedout) {
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (!u->request_sent && rp_http_upstream_test_connect(c) != RP_OK) {
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (u->buffer.start == NULL) {
        u->buffer.start = rp_palloc(r->pool, u->conf->buffer_size);
        if (u->buffer.start == NULL) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
        u->buffer.end = u->buffer.start + u->conf->buffer_size;
        u->buffer.temporary = 1;

        u->buffer.tag = u->output.tag;

        if (rp_list_init(&u->headers_in.headers, r->pool, 8,
                          sizeof(rp_table_elt_t))
            != RP_OK)
        {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rp_list_init(&u->headers_in.trailers, r->pool, 2,
                          sizeof(rp_table_elt_t))
            != RP_OK)
        {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

#if (RP_HTTP_CACHE)

        if (r->cache) {
            u->buffer.pos += r->cache->header_start;
            u->buffer.last = u->buffer.pos;
        }
#endif
    }

    for ( ;; ) {

        n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);

        if (n == RP_AGAIN) {
#if 0
            rp_add_timer(rev, u->read_timeout);
#endif

            if (rp_handle_read_event(c->read, 0) != RP_OK) {
                rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            return;
        }

        if (n == 0) {
            rp_log_error(RP_LOG_ERR, c->log, 0,
                          "upstream prematurely closed connection");
        }

        if (n == RP_ERROR || n == 0) {
            rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_ERROR);
            return;
        }

        u->state->bytes_received += n;

        u->buffer.last += n;

#if 0
        u->valid_header_in = 0;

        u->peer.cached = 0;
#endif

        rc = u->process_header(r);

        if (rc == RP_AGAIN) {

            if (u->buffer.last == u->buffer.end) {
                rp_log_error(RP_LOG_ERR, c->log, 0,
                              "upstream sent too big header");

                rp_http_upstream_next(r, u,
                                       RP_HTTP_UPSTREAM_FT_INVALID_HEADER);
                return;
            }

            continue;
        }

        break;
    }

    if (rc == RP_HTTP_UPSTREAM_INVALID_HEADER) {
        rp_http_upstream_next(r, u, RP_HTTP_UPSTREAM_FT_INVALID_HEADER);
        return;
    }

    if (rc == RP_ERROR) {
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* rc == RP_OK */

    u->state->header_time = rp_current_msec - u->start_time;

    if (u->headers_in.status_n >= RP_HTTP_SPECIAL_RESPONSE) {

        if (rp_http_upstream_test_next(r, u) == RP_OK) {
            return;
        }

        if (rp_http_upstream_intercept_errors(r, u) == RP_OK) {
            return;
        }
    }

    if (rp_http_upstream_process_headers(r, u) != RP_OK) {
        return;
    }

    rp_http_upstream_send_response(r, u);
}


static rp_int_t
rp_http_upstream_test_next(rp_http_request_t *r, rp_http_upstream_t *u)
{
    rp_msec_t                 timeout;
    rp_uint_t                 status, mask;
    rp_http_upstream_next_t  *un;

    status = u->headers_in.status_n;

    for (un = rp_http_upstream_next_errors; un->status; un++) {

        if (status != un->status) {
            continue;
        }

        timeout = u->conf->next_upstream_timeout;

        if (u->request_sent
            && (r->method & (RP_HTTP_POST|RP_HTTP_LOCK|RP_HTTP_PATCH)))
        {
            mask = un->mask | RP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;

        } else {
            mask = un->mask;
        }

        if (u->peer.tries > 1
            && ((u->conf->next_upstream & mask) == mask)
            && !(u->request_sent && r->request_body_no_buffering)
            && !(timeout && rp_current_msec - u->peer.start_time >= timeout))
        {
            rp_http_upstream_next(r, u, un->mask);
            return RP_OK;
        }

#if (RP_HTTP_CACHE)

        if (u->cache_status == RP_HTTP_CACHE_EXPIRED
            && ((u->conf->cache_use_stale & un->mask) || r->cache->stale_error))
        {
            rp_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != RP_OK) {
                rp_http_upstream_finalize_request(r, u, rc);
                return RP_OK;
            }

            u->cache_status = RP_HTTP_CACHE_STALE;
            rc = rp_http_upstream_cache_send(r, u);

            if (rc == RP_DONE) {
                return RP_OK;
            }

            if (rc == RP_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = RP_HTTP_INTERNAL_SERVER_ERROR;
            }

            rp_http_upstream_finalize_request(r, u, rc);
            return RP_OK;
        }

#endif
    }

#if (RP_HTTP_CACHE)

    if (status == RP_HTTP_NOT_MODIFIED
        && u->cache_status == RP_HTTP_CACHE_EXPIRED
        && u->conf->cache_revalidate)
    {
        time_t     now, valid, updating, error;
        rp_int_t  rc;

        rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream not modified");

        now = rp_time();

        valid = r->cache->valid_sec;
        updating = r->cache->updating_sec;
        error = r->cache->error_sec;

        rc = u->reinit_request(r);

        if (rc != RP_OK) {
            rp_http_upstream_finalize_request(r, u, rc);
            return RP_OK;
        }

        u->cache_status = RP_HTTP_CACHE_REVALIDATED;
        rc = rp_http_upstream_cache_send(r, u);

        if (rc == RP_DONE) {
            return RP_OK;
        }

        if (rc == RP_HTTP_UPSTREAM_INVALID_HEADER) {
            rc = RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (valid == 0) {
            valid = r->cache->valid_sec;
            updating = r->cache->updating_sec;
            error = r->cache->error_sec;
        }

        if (valid == 0) {
            valid = rp_http_file_cache_valid(u->conf->cache_valid,
                                              u->headers_in.status_n);
            if (valid) {
                valid = now + valid;
            }
        }

        if (valid) {
            r->cache->valid_sec = valid;
            r->cache->updating_sec = updating;
            r->cache->error_sec = error;

            r->cache->date = now;

            rp_http_file_cache_update_header(r);
        }

        rp_http_upstream_finalize_request(r, u, rc);
        return RP_OK;
    }

#endif

    return RP_DECLINED;
}


static rp_int_t
rp_http_upstream_intercept_errors(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    rp_int_t                  status;
    rp_uint_t                 i;
    rp_table_elt_t           *h;
    rp_http_err_page_t       *err_page;
    rp_http_core_loc_conf_t  *clcf;

    status = u->headers_in.status_n;

    if (status == RP_HTTP_NOT_FOUND && u->conf->intercept_404) {
        rp_http_upstream_finalize_request(r, u, RP_HTTP_NOT_FOUND);
        return RP_OK;
    }

    if (!u->conf->intercept_errors) {
        return RP_DECLINED;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->error_pages == NULL) {
        return RP_DECLINED;
    }

    err_page = clcf->error_pages->elts;
    for (i = 0; i < clcf->error_pages->nelts; i++) {

        if (err_page[i].status == status) {

            if (status == RP_HTTP_UNAUTHORIZED
                && u->headers_in.www_authenticate)
            {
                h = rp_list_push(&r->headers_out.headers);

                if (h == NULL) {
                    rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
                    return RP_OK;
                }

                *h = *u->headers_in.www_authenticate;

                r->headers_out.www_authenticate = h;
            }

#if (RP_HTTP_CACHE)

            if (r->cache) {

                if (u->cacheable) {
                    time_t  valid;

                    valid = r->cache->valid_sec;

                    if (valid == 0) {
                        valid = rp_http_file_cache_valid(u->conf->cache_valid,
                                                          status);
                        if (valid) {
                            r->cache->valid_sec = rp_time() + valid;
                        }
                    }

                    if (valid) {
                        r->cache->error = status;
                    }
                }

                rp_http_file_cache_free(r->cache, u->pipe->temp_file);
            }
#endif
            rp_http_upstream_finalize_request(r, u, status);

            return RP_OK;
        }
    }

    return RP_DECLINED;
}


static rp_int_t
rp_http_upstream_test_connect(rp_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (RP_HAVE_KQUEUE)

    if (rp_event_flags & RP_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) rp_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return RP_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = rp_socket_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) rp_connection_error(c, err, "connect() failed");
            return RP_ERROR;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_headers(rp_http_request_t *r, rp_http_upstream_t *u)
{
    rp_str_t                       uri, args;
    rp_uint_t                      i, flags;
    rp_list_part_t                *part;
    rp_table_elt_t                *h;
    rp_http_upstream_header_t     *hh;
    rp_http_upstream_main_conf_t  *umcf;

    umcf = rp_http_get_module_main_conf(r, rp_http_upstream_module);

    if (u->headers_in.x_accel_redirect
        && !(u->conf->ignore_headers & RP_HTTP_UPSTREAM_IGN_XA_REDIRECT))
    {
        rp_http_upstream_finalize_request(r, u, RP_DECLINED);

        part = &u->headers_in.headers.part;
        h = part->elts;

        for (i = 0; /* void */; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                h = part->elts;
                i = 0;
            }

            hh = rp_hash_find(&umcf->headers_in_hash, h[i].hash,
                               h[i].lowcase_key, h[i].key.len);

            if (hh && hh->redirect) {
                if (hh->copy_handler(r, &h[i], hh->conf) != RP_OK) {
                    rp_http_finalize_request(r,
                                              RP_HTTP_INTERNAL_SERVER_ERROR);
                    return RP_DONE;
                }
            }
        }

        uri = u->headers_in.x_accel_redirect->value;

        if (uri.data[0] == '@') {
            rp_http_named_location(r, &uri);

        } else {
            rp_str_null(&args);
            flags = RP_HTTP_LOG_UNSAFE;

            if (rp_http_parse_unsafe_uri(r, &uri, &args, &flags) != RP_OK) {
                rp_http_finalize_request(r, RP_HTTP_NOT_FOUND);
                return RP_DONE;
            }

            if (r->method != RP_HTTP_HEAD) {
                r->method = RP_HTTP_GET;
                r->method_name = rp_http_core_get_method;
            }

            rp_http_internal_redirect(r, &uri, &args);
        }

        rp_http_finalize_request(r, RP_DONE);
        return RP_DONE;
    }

    part = &u->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (rp_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        hh = rp_hash_find(&umcf->headers_in_hash, h[i].hash,
                           h[i].lowcase_key, h[i].key.len);

        if (hh) {
            if (hh->copy_handler(r, &h[i], hh->conf) != RP_OK) {
                rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
                return RP_DONE;
            }

            continue;
        }

        if (rp_http_upstream_copy_header_line(r, &h[i], 0) != RP_OK) {
            rp_http_upstream_finalize_request(r, u,
                                               RP_HTTP_INTERNAL_SERVER_ERROR);
            return RP_DONE;
        }
    }

    if (r->headers_out.server && r->headers_out.server->value.data == NULL) {
        r->headers_out.server->hash = 0;
    }

    if (r->headers_out.date && r->headers_out.date->value.data == NULL) {
        r->headers_out.date->hash = 0;
    }

    r->headers_out.status = u->headers_in.status_n;
    r->headers_out.status_line = u->headers_in.status_line;

    r->headers_out.content_length_n = u->headers_in.content_length_n;

    r->disable_not_modified = !u->cacheable;

    if (u->conf->force_ranges) {
        r->allow_ranges = 1;
        r->single_range = 1;

#if (RP_HTTP_CACHE)
        if (r->cached) {
            r->single_range = 0;
        }
#endif
    }

    u->length = -1;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_trailers(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    rp_uint_t        i;
    rp_list_part_t  *part;
    rp_table_elt_t  *h, *ho;

    if (!u->conf->pass_trailers) {
        return RP_OK;
    }

    part = &u->headers_in.trailers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (rp_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        ho = rp_list_push(&r->headers_out.trailers);
        if (ho == NULL) {
            return RP_ERROR;
        }

        *ho = h[i];
    }

    return RP_OK;
}


static void
rp_http_upstream_send_response(rp_http_request_t *r, rp_http_upstream_t *u)
{
    ssize_t                    n;
    rp_int_t                  rc;
    rp_event_pipe_t          *p;
    rp_connection_t          *c;
    rp_http_core_loc_conf_t  *clcf;

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || rc > RP_OK || r->post_action) {
        rp_http_upstream_finalize_request(r, u, rc);
        return;
    }

    u->header_sent = 1;

    if (u->upgrade) {

#if (RP_HTTP_CACHE)

        if (r->cache) {
            rp_http_file_cache_free(r->cache, u->pipe->temp_file);
        }

#endif

        rp_http_upstream_upgrade(r, u);
        return;
    }

    c = r->connection;

    if (r->header_only) {

        if (!u->buffering) {
            rp_http_upstream_finalize_request(r, u, rc);
            return;
        }

        if (!u->cacheable && !u->store) {
            rp_http_upstream_finalize_request(r, u, rc);
            return;
        }

        u->pipe->downstream_error = 1;
    }

    if (r->request_body && r->request_body->temp_file
        && r == r->main && !r->preserve_body
        && !u->conf->preserve_output)
    {
        rp_pool_run_cleanup_file(r->pool, r->request_body->temp_file->file.fd);
        r->request_body->temp_file->file.fd = RP_INVALID_FILE;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (!u->buffering) {

#if (RP_HTTP_CACHE)

        if (r->cache) {
            rp_http_file_cache_free(r->cache, u->pipe->temp_file);
        }

#endif

        if (u->input_filter == NULL) {
            u->input_filter_init = rp_http_upstream_non_buffered_filter_init;
            u->input_filter = rp_http_upstream_non_buffered_filter;
            u->input_filter_ctx = r;
        }

        u->read_event_handler = rp_http_upstream_process_non_buffered_upstream;
        r->write_event_handler =
                             rp_http_upstream_process_non_buffered_downstream;

        r->limit_rate = 0;
        r->limit_rate_set = 1;

        if (u->input_filter_init(u->input_filter_ctx) == RP_ERROR) {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
            return;
        }

        if (clcf->tcp_nodelay && rp_tcp_nodelay(c) != RP_OK) {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
            return;
        }

        n = u->buffer.last - u->buffer.pos;

        if (n) {
            u->buffer.last = u->buffer.pos;

            u->state->response_length += n;

            if (u->input_filter(u->input_filter_ctx, n) == RP_ERROR) {
                rp_http_upstream_finalize_request(r, u, RP_ERROR);
                return;
            }

            rp_http_upstream_process_non_buffered_downstream(r);

        } else {
            u->buffer.pos = u->buffer.start;
            u->buffer.last = u->buffer.start;

            if (rp_http_send_special(r, RP_HTTP_FLUSH) == RP_ERROR) {
                rp_http_upstream_finalize_request(r, u, RP_ERROR);
                return;
            }

            if (u->peer.connection->read->ready || u->length == 0) {
                rp_http_upstream_process_non_buffered_upstream(r, u);
            }
        }

        return;
    }

    /* TODO: preallocate event_pipe bufs, look "Content-Length" */

#if (RP_HTTP_CACHE)

    if (r->cache && r->cache->file.fd != RP_INVALID_FILE) {
        rp_pool_run_cleanup_file(r->pool, r->cache->file.fd);
        r->cache->file.fd = RP_INVALID_FILE;
    }

    switch (rp_http_test_predicates(r, u->conf->no_cache)) {

    case RP_ERROR:
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;

    case RP_DECLINED:
        u->cacheable = 0;
        break;

    default: /* RP_OK */

        if (u->cache_status == RP_HTTP_CACHE_BYPASS) {

            /* create cache if previously bypassed */

            if (rp_http_file_cache_create(r) != RP_OK) {
                rp_http_upstream_finalize_request(r, u, RP_ERROR);
                return;
            }
        }

        break;
    }

    if (u->cacheable) {
        time_t  now, valid;

        now = rp_time();

        valid = r->cache->valid_sec;

        if (valid == 0) {
            valid = rp_http_file_cache_valid(u->conf->cache_valid,
                                              u->headers_in.status_n);
            if (valid) {
                r->cache->valid_sec = now + valid;
            }
        }

        if (valid) {
            r->cache->date = now;
            r->cache->body_start = (u_short) (u->buffer.pos - u->buffer.start);

            if (u->headers_in.status_n == RP_HTTP_OK
                || u->headers_in.status_n == RP_HTTP_PARTIAL_CONTENT)
            {
                r->cache->last_modified = u->headers_in.last_modified_time;

                if (u->headers_in.etag) {
                    r->cache->etag = u->headers_in.etag->value;

                } else {
                    rp_str_null(&r->cache->etag);
                }

            } else {
                r->cache->last_modified = -1;
                rp_str_null(&r->cache->etag);
            }

            if (rp_http_file_cache_set_header(r, u->buffer.start) != RP_OK) {
                rp_http_upstream_finalize_request(r, u, RP_ERROR);
                return;
            }

        } else {
            u->cacheable = 0;
        }
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http cacheable: %d", u->cacheable);

    if (u->cacheable == 0 && r->cache) {
        rp_http_file_cache_free(r->cache, u->pipe->temp_file);
    }

    if (r->header_only && !u->cacheable && !u->store) {
        rp_http_upstream_finalize_request(r, u, 0);
        return;
    }

#endif

    p = u->pipe;

    p->output_filter = rp_http_upstream_output_filter;
    p->output_ctx = r;
    p->tag = u->output.tag;
    p->bufs = u->conf->bufs;
    p->busy_size = u->conf->busy_buffers_size;
    p->upstream = u->peer.connection;
    p->downstream = c;
    p->pool = r->pool;
    p->log = c->log;
    p->limit_rate = u->conf->limit_rate;
    p->start_sec = rp_time();

    p->cacheable = u->cacheable || u->store;

    p->temp_file = rp_pcalloc(r->pool, sizeof(rp_temp_file_t));
    if (p->temp_file == NULL) {
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    p->temp_file->file.fd = RP_INVALID_FILE;
    p->temp_file->file.log = c->log;
    p->temp_file->path = u->conf->temp_path;
    p->temp_file->pool = r->pool;

    if (p->cacheable) {
        p->temp_file->persistent = 1;

#if (RP_HTTP_CACHE)
        if (r->cache && !r->cache->file_cache->use_temp_path) {
            p->temp_file->path = r->cache->file_cache->path;
            p->temp_file->file.name = r->cache->file.name;
        }
#endif

    } else {
        p->temp_file->log_level = RP_LOG_WARN;
        p->temp_file->warn = "an upstream response is buffered "
                             "to a temporary file";
    }

    p->max_temp_file_size = u->conf->max_temp_file_size;
    p->temp_file_write_size = u->conf->temp_file_write_size;

#if (RP_THREADS)
    if (clcf->aio == RP_HTTP_AIO_THREADS && clcf->aio_write) {
        p->thread_handler = rp_http_upstream_thread_handler;
        p->thread_ctx = r;
    }
#endif

    p->preread_bufs = rp_alloc_chain_link(r->pool);
    if (p->preread_bufs == NULL) {
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    p->preread_bufs->buf = &u->buffer;
    p->preread_bufs->next = NULL;
    u->buffer.recycled = 1;

    p->preread_size = u->buffer.last - u->buffer.pos;

    if (u->cacheable) {

        p->buf_to_file = rp_calloc_buf(r->pool);
        if (p->buf_to_file == NULL) {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
            return;
        }

        p->buf_to_file->start = u->buffer.start;
        p->buf_to_file->pos = u->buffer.start;
        p->buf_to_file->last = u->buffer.pos;
        p->buf_to_file->temporary = 1;
    }

    if (rp_event_flags & RP_USE_IOCP_EVENT) {
        /* the posted aio operation may corrupt a shadow buffer */
        p->single_buf = 1;
    }

    /* TODO: p->free_bufs = 0 if use rp_create_chain_of_bufs() */
    p->free_bufs = 1;

    /*
     * event_pipe would do u->buffer.last += p->preread_size
     * as though these bytes were read
     */
    u->buffer.last = u->buffer.pos;

    if (u->conf->cyclic_temp_file) {

        /*
         * we need to disable the use of sendfile() if we use cyclic temp file
         * because the writing a new data may interfere with sendfile()
         * that uses the same kernel file pages (at least on FreeBSD)
         */

        p->cyclic_temp_file = 1;
        c->sendfile = 0;

    } else {
        p->cyclic_temp_file = 0;
    }

    p->read_timeout = u->conf->read_timeout;
    p->send_timeout = clcf->send_timeout;
    p->send_lowat = clcf->send_lowat;

    p->length = -1;

    if (u->input_filter_init
        && u->input_filter_init(p->input_ctx) != RP_OK)
    {
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    u->read_event_handler = rp_http_upstream_process_upstream;
    r->write_event_handler = rp_http_upstream_process_downstream;

    rp_http_upstream_process_upstream(r, u);
}


static void
rp_http_upstream_upgrade(rp_http_request_t *r, rp_http_upstream_t *u)
{
    rp_connection_t          *c;
    rp_http_core_loc_conf_t  *clcf;

    c = r->connection;
    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    /* TODO: prevent upgrade if not requested or not possible */

    if (r != r->main) {
        rp_log_error(RP_LOG_ERR, c->log, 0,
                      "connection upgrade in subrequest");
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    r->keepalive = 0;
    c->log->action = "proxying upgraded connection";

    u->read_event_handler = rp_http_upstream_upgraded_read_upstream;
    u->write_event_handler = rp_http_upstream_upgraded_write_upstream;
    r->read_event_handler = rp_http_upstream_upgraded_read_downstream;
    r->write_event_handler = rp_http_upstream_upgraded_write_downstream;

    if (clcf->tcp_nodelay) {

        if (rp_tcp_nodelay(c) != RP_OK) {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
            return;
        }

        if (rp_tcp_nodelay(u->peer.connection) != RP_OK) {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
            return;
        }
    }

    if (rp_http_send_special(r, RP_HTTP_FLUSH) == RP_ERROR) {
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    if (u->peer.connection->read->ready
        || u->buffer.pos != u->buffer.last)
    {
        rp_post_event(c->read, &rp_posted_events);
        rp_http_upstream_process_upgraded(r, 1, 1);
        return;
    }

    rp_http_upstream_process_upgraded(r, 0, 1);
}


static void
rp_http_upstream_upgraded_read_downstream(rp_http_request_t *r)
{
    rp_http_upstream_process_upgraded(r, 0, 0);
}


static void
rp_http_upstream_upgraded_write_downstream(rp_http_request_t *r)
{
    rp_http_upstream_process_upgraded(r, 1, 1);
}


static void
rp_http_upstream_upgraded_read_upstream(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    rp_http_upstream_process_upgraded(r, 1, 0);
}


static void
rp_http_upstream_upgraded_write_upstream(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    rp_http_upstream_process_upgraded(r, 0, 1);
}


static void
rp_http_upstream_process_upgraded(rp_http_request_t *r,
    rp_uint_t from_upstream, rp_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    rp_buf_t                 *b;
    rp_uint_t                 flags;
    rp_connection_t          *c, *downstream, *upstream, *dst, *src;
    rp_http_upstream_t       *u;
    rp_http_core_loc_conf_t  *clcf;

    c = r->connection;
    u = r->upstream;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upgraded, fu:%ui", from_upstream);

    downstream = c;
    upstream = u->peer.connection;

    if (downstream->write->timedout) {
        c->timedout = 1;
        rp_connection_error(c, RP_ETIMEDOUT, "client timed out");
        rp_http_upstream_finalize_request(r, u, RP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (upstream->read->timedout || upstream->write->timedout) {
        rp_connection_error(c, RP_ETIMEDOUT, "upstream timed out");
        rp_http_upstream_finalize_request(r, u, RP_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    if (from_upstream) {
        src = upstream;
        dst = downstream;
        b = &u->buffer;

    } else {
        src = downstream;
        dst = upstream;
        b = &u->from_client;

        if (r->header_in->last > r->header_in->pos) {
            b = r->header_in;
            b->end = b->last;
            do_write = 1;
        }

        if (b->start == NULL) {
            b->start = rp_palloc(r->pool, u->conf->buffer_size);
            if (b->start == NULL) {
                rp_http_upstream_finalize_request(r, u, RP_ERROR);
                return;
            }

            b->pos = b->start;
            b->last = b->start;
            b->end = b->start + u->conf->buffer_size;
            b->temporary = 1;
            b->tag = u->output.tag;
        }
    }

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {

                n = dst->send(dst, b->pos, size);

                if (n == RP_ERROR) {
                    rp_http_upstream_finalize_request(r, u, RP_ERROR);
                    return;
                }

                if (n > 0) {
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {

            n = src->recv(src, b->last, size);

            if (n == RP_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                if (from_upstream) {
                    u->state->bytes_received += n;
                }

                continue;
            }

            if (n == RP_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    if ((upstream->read->eof && u->buffer.pos == u->buffer.last)
        || (downstream->read->eof && u->from_client.pos == u->from_client.last)
        || (downstream->read->eof && upstream->read->eof))
    {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream upgraded done");
        rp_http_upstream_finalize_request(r, u, 0);
        return;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (rp_handle_write_event(upstream->write, u->conf->send_lowat)
        != RP_OK)
    {
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    if (upstream->write->active && !upstream->write->ready) {
        rp_add_timer(upstream->write, u->conf->send_timeout);

    } else if (upstream->write->timer_set) {
        rp_del_timer(upstream->write);
    }

    if (upstream->read->eof || upstream->read->error) {
        flags = RP_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (rp_handle_read_event(upstream->read, flags) != RP_OK) {
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        rp_add_timer(upstream->read, u->conf->read_timeout);

    } else if (upstream->read->timer_set) {
        rp_del_timer(upstream->read);
    }

    if (rp_handle_write_event(downstream->write, clcf->send_lowat)
        != RP_OK)
    {
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    if (downstream->read->eof || downstream->read->error) {
        flags = RP_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (rp_handle_read_event(downstream->read, flags) != RP_OK) {
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    if (downstream->write->active && !downstream->write->ready) {
        rp_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        rp_del_timer(downstream->write);
    }
}


static void
rp_http_upstream_process_non_buffered_downstream(rp_http_request_t *r)
{
    rp_event_t          *wev;
    rp_connection_t     *c;
    rp_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    wev = c->write;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered downstream");

    c->log->action = "sending to client";

    if (wev->timedout) {
        c->timedout = 1;
        rp_connection_error(c, RP_ETIMEDOUT, "client timed out");
        rp_http_upstream_finalize_request(r, u, RP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rp_http_upstream_process_non_buffered_request(r, 1);
}


static void
rp_http_upstream_process_non_buffered_upstream(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    rp_connection_t  *c;

    c = u->peer.connection;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered upstream");

    c->log->action = "reading upstream";

    if (c->read->timedout) {
        rp_connection_error(c, RP_ETIMEDOUT, "upstream timed out");
        rp_http_upstream_finalize_request(r, u, RP_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    rp_http_upstream_process_non_buffered_request(r, 0);
}


static void
rp_http_upstream_process_non_buffered_request(rp_http_request_t *r,
    rp_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    rp_buf_t                 *b;
    rp_int_t                  rc;
    rp_uint_t                 flags;
    rp_connection_t          *downstream, *upstream;
    rp_http_upstream_t       *u;
    rp_http_core_loc_conf_t  *clcf;

    u = r->upstream;
    downstream = r->connection;
    upstream = u->peer.connection;

    b = &u->buffer;

    do_write = do_write || u->length == 0;

    for ( ;; ) {

        if (do_write) {

            if (u->out_bufs || u->busy_bufs || downstream->buffered) {
                rc = rp_http_output_filter(r, u->out_bufs);

                if (rc == RP_ERROR) {
                    rp_http_upstream_finalize_request(r, u, RP_ERROR);
                    return;
                }

                rp_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,
                                        &u->out_bufs, u->output.tag);
            }

            if (u->busy_bufs == NULL) {

                if (u->length == 0
                    || (upstream->read->eof && u->length == -1))
                {
                    rp_http_upstream_finalize_request(r, u, 0);
                    return;
                }

                if (upstream->read->eof) {
                    rp_log_error(RP_LOG_ERR, upstream->log, 0,
                                  "upstream prematurely closed connection");

                    rp_http_upstream_finalize_request(r, u,
                                                       RP_HTTP_BAD_GATEWAY);
                    return;
                }

                if (upstream->read->error) {
                    rp_http_upstream_finalize_request(r, u,
                                                       RP_HTTP_BAD_GATEWAY);
                    return;
                }

                b->pos = b->start;
                b->last = b->start;
            }
        }

        size = b->end - b->last;

        if (size && upstream->read->ready) {

            n = upstream->recv(upstream, b->last, size);

            if (n == RP_AGAIN) {
                break;
            }

            if (n > 0) {
                u->state->bytes_received += n;
                u->state->response_length += n;

                if (u->input_filter(u->input_filter_ctx, n) == RP_ERROR) {
                    rp_http_upstream_finalize_request(r, u, RP_ERROR);
                    return;
                }
            }

            do_write = 1;

            continue;
        }

        break;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (downstream->data == r) {
        if (rp_handle_write_event(downstream->write, clcf->send_lowat)
            != RP_OK)
        {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
            return;
        }
    }

    if (downstream->write->active && !downstream->write->ready) {
        rp_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        rp_del_timer(downstream->write);
    }

    if (upstream->read->eof || upstream->read->error) {
        flags = RP_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (rp_handle_read_event(upstream->read, flags) != RP_OK) {
        rp_http_upstream_finalize_request(r, u, RP_ERROR);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        rp_add_timer(upstream->read, u->conf->read_timeout);

    } else if (upstream->read->timer_set) {
        rp_del_timer(upstream->read);
    }
}


static rp_int_t
rp_http_upstream_non_buffered_filter_init(void *data)
{
    return RP_OK;
}


static rp_int_t
rp_http_upstream_non_buffered_filter(void *data, ssize_t bytes)
{
    rp_http_request_t  *r = data;

    rp_buf_t            *b;
    rp_chain_t          *cl, **ll;
    rp_http_upstream_t  *u;

    u = r->upstream;

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rp_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return RP_ERROR;
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
        return RP_OK;
    }

    u->length -= bytes;

    return RP_OK;
}


#if (RP_THREADS)

static rp_int_t
rp_http_upstream_thread_handler(rp_thread_task_t *task, rp_file_t *file)
{
    rp_str_t                  name;
    rp_event_pipe_t          *p;
    rp_thread_pool_t         *tp;
    rp_http_request_t        *r;
    rp_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;
    p = r->upstream->pipe;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (rp_http_complex_value(r, clcf->thread_pool_value, &name)
            != RP_OK)
        {
            return RP_ERROR;
        }

        tp = rp_thread_pool_get((rp_cycle_t *) rp_cycle, &name);

        if (tp == NULL) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return RP_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = rp_http_upstream_thread_event_handler;

    if (rp_thread_task_post(tp, task) != RP_OK) {
        return RP_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;
    p->aio = 1;

    return RP_OK;
}


static void
rp_http_upstream_thread_event_handler(rp_event_t *ev)
{
    rp_connection_t    *c;
    rp_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    rp_http_set_log_request(c->log, r);

    rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream thread: \"%V?%V\"", &r->uri, &r->args);

    r->main->blocked--;
    r->aio = 0;

    if (r->done) {
        /*
         * trigger connection event handler if the subrequest was
         * already finalized; this can happen if the handler is used
         * for sendfile() in threads
         */

        c->write->handler(c->write);

    } else {
        r->write_event_handler(r);
        rp_http_run_posted_requests(c);
    }
}

#endif


static rp_int_t
rp_http_upstream_output_filter(void *data, rp_chain_t *chain)
{
    rp_int_t            rc;
    rp_event_pipe_t    *p;
    rp_http_request_t  *r;

    r = data;
    p = r->upstream->pipe;

    rc = rp_http_output_filter(r, chain);

    p->aio = r->aio;

    return rc;
}


static void
rp_http_upstream_process_downstream(rp_http_request_t *r)
{
    rp_event_t          *wev;
    rp_connection_t     *c;
    rp_event_pipe_t     *p;
    rp_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    p = u->pipe;
    wev = c->write;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process downstream");

    c->log->action = "sending to client";

#if (RP_THREADS)
    p->aio = r->aio;
#endif

    if (wev->timedout) {

        p->downstream_error = 1;
        c->timedout = 1;
        rp_connection_error(c, RP_ETIMEDOUT, "client timed out");

    } else {

        if (wev->delayed) {

            rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                           "http downstream delayed");

            if (rp_handle_write_event(wev, p->send_lowat) != RP_OK) {
                rp_http_upstream_finalize_request(r, u, RP_ERROR);
            }

            return;
        }

        if (rp_event_pipe(p, 1) == RP_ABORT) {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
            return;
        }
    }

    rp_http_upstream_process_request(r, u);
}


static void
rp_http_upstream_process_upstream(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    rp_event_t       *rev;
    rp_event_pipe_t  *p;
    rp_connection_t  *c;

    c = u->peer.connection;
    p = u->pipe;
    rev = c->read;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upstream");

    c->log->action = "reading upstream";

    if (rev->timedout) {

        p->upstream_error = 1;
        rp_connection_error(c, RP_ETIMEDOUT, "upstream timed out");

    } else {

        if (rev->delayed) {

            rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                           "http upstream delayed");

            if (rp_handle_read_event(rev, 0) != RP_OK) {
                rp_http_upstream_finalize_request(r, u, RP_ERROR);
            }

            return;
        }

        if (rp_event_pipe(p, 0) == RP_ABORT) {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
            return;
        }
    }

    rp_http_upstream_process_request(r, u);
}


static void
rp_http_upstream_process_request(rp_http_request_t *r,
    rp_http_upstream_t *u)
{
    rp_temp_file_t   *tf;
    rp_event_pipe_t  *p;

    p = u->pipe;

#if (RP_THREADS)

    if (p->writing && !p->aio) {

        /*
         * make sure to call rp_event_pipe()
         * if there is an incomplete aio write
         */

        if (rp_event_pipe(p, 1) == RP_ABORT) {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
            return;
        }
    }

    if (p->writing) {
        return;
    }

#endif

    if (u->peer.connection) {

        if (u->store) {

            if (p->upstream_eof || p->upstream_done) {

                tf = p->temp_file;

                if (u->headers_in.status_n == RP_HTTP_OK
                    && (p->upstream_done || p->length == -1)
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n == tf->offset))
                {
                    rp_http_upstream_store(r, u);
                }
            }
        }

#if (RP_HTTP_CACHE)

        if (u->cacheable) {

            if (p->upstream_done) {
                rp_http_file_cache_update(r, p->temp_file);

            } else if (p->upstream_eof) {

                tf = p->temp_file;

                if (p->length == -1
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n
                           == tf->offset - (off_t) r->cache->body_start))
                {
                    rp_http_file_cache_update(r, tf);

                } else {
                    rp_http_file_cache_free(r->cache, tf);
                }

            } else if (p->upstream_error) {
                rp_http_file_cache_free(r->cache, p->temp_file);
            }
        }

#endif

        if (p->upstream_done || p->upstream_eof || p->upstream_error) {
            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http upstream exit: %p", p->out);

            if (p->upstream_done
                || (p->upstream_eof && p->length == -1))
            {
                rp_http_upstream_finalize_request(r, u, 0);
                return;
            }

            if (p->upstream_eof) {
                rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                              "upstream prematurely closed connection");
            }

            rp_http_upstream_finalize_request(r, u, RP_HTTP_BAD_GATEWAY);
            return;
        }
    }

    if (p->downstream_error) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream downstream error");

        if (!u->cacheable && !u->store && u->peer.connection) {
            rp_http_upstream_finalize_request(r, u, RP_ERROR);
        }
    }
}


static void
rp_http_upstream_store(rp_http_request_t *r, rp_http_upstream_t *u)
{
    size_t                  root;
    time_t                  lm;
    rp_str_t               path;
    rp_temp_file_t        *tf;
    rp_ext_rename_file_t   ext;

    tf = u->pipe->temp_file;

    if (tf->file.fd == RP_INVALID_FILE) {

        /* create file for empty 200 response */

        tf = rp_pcalloc(r->pool, sizeof(rp_temp_file_t));
        if (tf == NULL) {
            return;
        }

        tf->file.fd = RP_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = u->conf->temp_path;
        tf->pool = r->pool;
        tf->persistent = 1;

        if (rp_create_temp_file(&tf->file, tf->path, tf->pool,
                                 tf->persistent, tf->clean, tf->access)
            != RP_OK)
        {
            return;
        }

        u->pipe->temp_file = tf;
    }

    ext.access = u->conf->store_access;
    ext.path_access = u->conf->store_access;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (u->headers_in.last_modified) {

        lm = rp_parse_http_time(u->headers_in.last_modified->value.data,
                                 u->headers_in.last_modified->value.len);

        if (lm != RP_ERROR) {
            ext.time = lm;
            ext.fd = tf->file.fd;
        }
    }

    if (u->conf->store_lengths == NULL) {

        if (rp_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            return;
        }

    } else {
        if (rp_http_script_run(r, &path, u->conf->store_lengths->elts, 0,
                                u->conf->store_values->elts)
            == NULL)
        {
            return;
        }
    }

    path.len--;

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream stores \"%s\" to \"%s\"",
                   tf->file.name.data, path.data);

    (void) rp_ext_rename_file(&tf->file.name, &path, &ext);

    u->store = 0;
}


static void
rp_http_upstream_dummy_handler(rp_http_request_t *r, rp_http_upstream_t *u)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream dummy handler");
}


static void
rp_http_upstream_next(rp_http_request_t *r, rp_http_upstream_t *u,
    rp_uint_t ft_type)
{
    rp_msec_t  timeout;
    rp_uint_t  status, state;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http next upstream, %xi", ft_type);

    if (u->peer.sockaddr) {

        if (u->peer.connection) {
            u->state->bytes_sent = u->peer.connection->sent;
        }

        if (ft_type == RP_HTTP_UPSTREAM_FT_HTTP_403
            || ft_type == RP_HTTP_UPSTREAM_FT_HTTP_404)
        {
            state = RP_PEER_NEXT;

        } else {
            state = RP_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (ft_type == RP_HTTP_UPSTREAM_FT_TIMEOUT) {
        rp_log_error(RP_LOG_ERR, r->connection->log, RP_ETIMEDOUT,
                      "upstream timed out");
    }

    if (u->peer.cached && ft_type == RP_HTTP_UPSTREAM_FT_ERROR) {
        /* TODO: inform balancer instead */
        u->peer.tries++;
    }

    switch (ft_type) {

    case RP_HTTP_UPSTREAM_FT_TIMEOUT:
    case RP_HTTP_UPSTREAM_FT_HTTP_504:
        status = RP_HTTP_GATEWAY_TIME_OUT;
        break;

    case RP_HTTP_UPSTREAM_FT_HTTP_500:
        status = RP_HTTP_INTERNAL_SERVER_ERROR;
        break;

    case RP_HTTP_UPSTREAM_FT_HTTP_503:
        status = RP_HTTP_SERVICE_UNAVAILABLE;
        break;

    case RP_HTTP_UPSTREAM_FT_HTTP_403:
        status = RP_HTTP_FORBIDDEN;
        break;

    case RP_HTTP_UPSTREAM_FT_HTTP_404:
        status = RP_HTTP_NOT_FOUND;
        break;

    case RP_HTTP_UPSTREAM_FT_HTTP_429:
        status = RP_HTTP_TOO_MANY_REQUESTS;
        break;

    /*
     * RP_HTTP_UPSTREAM_FT_BUSY_LOCK and RP_HTTP_UPSTREAM_FT_MAX_WAITING
     * never reach here
     */

    default:
        status = RP_HTTP_BAD_GATEWAY;
    }

    if (r->connection->error) {
        rp_http_upstream_finalize_request(r, u,
                                           RP_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    u->state->status = status;

    timeout = u->conf->next_upstream_timeout;

    if (u->request_sent
        && (r->method & (RP_HTTP_POST|RP_HTTP_LOCK|RP_HTTP_PATCH)))
    {
        ft_type |= RP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
    }

    if (u->peer.tries == 0
        || ((u->conf->next_upstream & ft_type) != ft_type)
        || (u->request_sent && r->request_body_no_buffering)
        || (timeout && rp_current_msec - u->peer.start_time >= timeout))
    {
#if (RP_HTTP_CACHE)

        if (u->cache_status == RP_HTTP_CACHE_EXPIRED
            && ((u->conf->cache_use_stale & ft_type) || r->cache->stale_error))
        {
            rp_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != RP_OK) {
                rp_http_upstream_finalize_request(r, u, rc);
                return;
            }

            u->cache_status = RP_HTTP_CACHE_STALE;
            rc = rp_http_upstream_cache_send(r, u);

            if (rc == RP_DONE) {
                return;
            }

            if (rc == RP_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = RP_HTTP_INTERNAL_SERVER_ERROR;
            }

            rp_http_upstream_finalize_request(r, u, rc);
            return;
        }
#endif

        rp_http_upstream_finalize_request(r, u, status);
        return;
    }

    if (u->peer.connection) {
        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);
#if (RP_HTTP_SSL)

        if (u->peer.connection->ssl) {
            u->peer.connection->ssl->no_wait_shutdown = 1;
            u->peer.connection->ssl->no_send_shutdown = 1;

            (void) rp_ssl_shutdown(u->peer.connection);
        }
#endif

        if (u->peer.connection->pool) {
            rp_destroy_pool(u->peer.connection->pool);
        }

        rp_close_connection(u->peer.connection);
        u->peer.connection = NULL;
    }

    rp_http_upstream_connect(r, u);
}


static void
rp_http_upstream_cleanup(void *data)
{
    rp_http_request_t *r = data;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cleanup http upstream request: \"%V\"", &r->uri);

    rp_http_upstream_finalize_request(r, r->upstream, RP_DONE);
}


static void
rp_http_upstream_finalize_request(rp_http_request_t *r,
    rp_http_upstream_t *u, rp_int_t rc)
{
    rp_uint_t  flush;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http upstream request: %i", rc);

    if (u->cleanup == NULL) {
        /* the request was already finalized */
        rp_http_finalize_request(r, RP_DONE);
        return;
    }

    *u->cleanup = NULL;
    u->cleanup = NULL;

    if (u->resolved && u->resolved->ctx) {
        rp_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->state && u->state->response_time == (rp_msec_t) -1) {
        u->state->response_time = rp_current_msec - u->start_time;

        if (u->pipe && u->pipe->read_length) {
            u->state->bytes_received += u->pipe->read_length
                                        - u->pipe->preread_size;
            u->state->response_length = u->pipe->read_length;
        }

        if (u->peer.connection) {
            u->state->bytes_sent = u->peer.connection->sent;
        }
    }

    u->finalize_request(r, rc);

    if (u->peer.free && u->peer.sockaddr) {
        u->peer.free(&u->peer, u->peer.data, 0);
        u->peer.sockaddr = NULL;
    }

    if (u->peer.connection) {

#if (RP_HTTP_SSL)

        /* TODO: do not shutdown persistent connection */

        if (u->peer.connection->ssl) {

            /*
             * We send the "close notify" shutdown alert to the upstream only
             * and do not wait its "close notify" shutdown alert.
             * It is acceptable according to the TLS standard.
             */

            u->peer.connection->ssl->no_wait_shutdown = 1;

            (void) rp_ssl_shutdown(u->peer.connection);
        }
#endif

        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            rp_destroy_pool(u->peer.connection->pool);
        }

        rp_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->pipe && u->pipe->temp_file) {
        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream temp fd: %d",
                       u->pipe->temp_file->file.fd);
    }

    if (u->store && u->pipe && u->pipe->temp_file
        && u->pipe->temp_file->file.fd != RP_INVALID_FILE)
    {
        if (rp_delete_file(u->pipe->temp_file->file.name.data)
            == RP_FILE_ERROR)
        {
            rp_log_error(RP_LOG_CRIT, r->connection->log, rp_errno,
                          rp_delete_file_n " \"%s\" failed",
                          u->pipe->temp_file->file.name.data);
        }
    }

#if (RP_HTTP_CACHE)

    if (r->cache) {

        if (u->cacheable) {

            if (rc == RP_HTTP_BAD_GATEWAY || rc == RP_HTTP_GATEWAY_TIME_OUT) {
                time_t  valid;

                valid = rp_http_file_cache_valid(u->conf->cache_valid, rc);

                if (valid) {
                    r->cache->valid_sec = rp_time() + valid;
                    r->cache->error = rc;
                }
            }
        }

        rp_http_file_cache_free(r->cache, u->pipe->temp_file);
    }

#endif

    r->read_event_handler = rp_http_block_reading;

    if (rc == RP_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (!u->header_sent
        || rc == RP_HTTP_REQUEST_TIME_OUT
        || rc == RP_HTTP_CLIENT_CLOSED_REQUEST)
    {
        rp_http_finalize_request(r, rc);
        return;
    }

    flush = 0;

    if (rc >= RP_HTTP_SPECIAL_RESPONSE) {
        rc = RP_ERROR;
        flush = 1;
    }

    if (r->header_only
        || (u->pipe && u->pipe->downstream_error))
    {
        rp_http_finalize_request(r, rc);
        return;
    }

    if (rc == 0) {

        if (rp_http_upstream_process_trailers(r, u) != RP_OK) {
            rp_http_finalize_request(r, RP_ERROR);
            return;
        }

        rc = rp_http_send_special(r, RP_HTTP_LAST);

    } else if (flush) {
        r->keepalive = 0;
        rc = rp_http_send_special(r, RP_HTTP_FLUSH);
    }

    rp_http_finalize_request(r, rc);
}


static rp_int_t
rp_http_upstream_process_header_line(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_table_elt_t  **ph;

    ph = (rp_table_elt_t **) ((char *) &r->upstream->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_ignore_header_line(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_content_length(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset)
{
    rp_http_upstream_t  *u;

    u = r->upstream;

    u->headers_in.content_length = h;
    u->headers_in.content_length_n = rp_atoof(h->value.data, h->value.len);

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_last_modified(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset)
{
    rp_http_upstream_t  *u;

    u = r->upstream;

    u->headers_in.last_modified = h;
    u->headers_in.last_modified_time = rp_parse_http_time(h->value.data,
                                                           h->value.len);

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_set_cookie(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_array_t           *pa;
    rp_table_elt_t      **ph;
    rp_http_upstream_t   *u;

    u = r->upstream;
    pa = &u->headers_in.cookies;

    if (pa->elts == NULL) {
        if (rp_array_init(pa, r->pool, 1, sizeof(rp_table_elt_t *)) != RP_OK)
        {
            return RP_ERROR;
        }
    }

    ph = rp_array_push(pa);
    if (ph == NULL) {
        return RP_ERROR;
    }

    *ph = h;

#if (RP_HTTP_CACHE)
    if (!(u->conf->ignore_headers & RP_HTTP_UPSTREAM_IGN_SET_COOKIE)) {
        u->cacheable = 0;
    }
#endif

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_cache_control(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset)
{
    rp_array_t          *pa;
    rp_table_elt_t     **ph;
    rp_http_upstream_t  *u;

    u = r->upstream;
    pa = &u->headers_in.cache_control;

    if (pa->elts == NULL) {
        if (rp_array_init(pa, r->pool, 2, sizeof(rp_table_elt_t *)) != RP_OK)
        {
            return RP_ERROR;
        }
    }

    ph = rp_array_push(pa);
    if (ph == NULL) {
        return RP_ERROR;
    }

    *ph = h;

#if (RP_HTTP_CACHE)
    {
    u_char     *p, *start, *last;
    rp_int_t   n;

    if (u->conf->ignore_headers & RP_HTTP_UPSTREAM_IGN_CACHE_CONTROL) {
        return RP_OK;
    }

    if (r->cache == NULL) {
        return RP_OK;
    }

    if (r->cache->valid_sec != 0 && u->headers_in.x_accel_expires != NULL) {
        return RP_OK;
    }

    start = h->value.data;
    last = start + h->value.len;

    if (rp_strlcasestrn(start, last, (u_char *) "no-cache", 8 - 1) != NULL
        || rp_strlcasestrn(start, last, (u_char *) "no-store", 8 - 1) != NULL
        || rp_strlcasestrn(start, last, (u_char *) "private", 7 - 1) != NULL)
    {
        u->cacheable = 0;
        return RP_OK;
    }

    p = rp_strlcasestrn(start, last, (u_char *) "s-maxage=", 9 - 1);
    offset = 9;

    if (p == NULL) {
        p = rp_strlcasestrn(start, last, (u_char *) "max-age=", 8 - 1);
        offset = 8;
    }

    if (p) {
        n = 0;

        for (p += offset; p < last; p++) {
            if (*p == ',' || *p == ';' || *p == ' ') {
                break;
            }

            if (*p >= '0' && *p <= '9') {
                n = n * 10 + (*p - '0');
                continue;
            }

            u->cacheable = 0;
            return RP_OK;
        }

        if (n == 0) {
            u->cacheable = 0;
            return RP_OK;
        }

        r->cache->valid_sec = rp_time() + n;
    }

    p = rp_strlcasestrn(start, last, (u_char *) "stale-while-revalidate=",
                         23 - 1);

    if (p) {
        n = 0;

        for (p += 23; p < last; p++) {
            if (*p == ',' || *p == ';' || *p == ' ') {
                break;
            }

            if (*p >= '0' && *p <= '9') {
                n = n * 10 + (*p - '0');
                continue;
            }

            u->cacheable = 0;
            return RP_OK;
        }

        r->cache->updating_sec = n;
        r->cache->error_sec = n;
    }

    p = rp_strlcasestrn(start, last, (u_char *) "stale-if-error=", 15 - 1);

    if (p) {
        n = 0;

        for (p += 15; p < last; p++) {
            if (*p == ',' || *p == ';' || *p == ' ') {
                break;
            }

            if (*p >= '0' && *p <= '9') {
                n = n * 10 + (*p - '0');
                continue;
            }

            u->cacheable = 0;
            return RP_OK;
        }

        r->cache->error_sec = n;
    }
    }
#endif

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_expires(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.expires = h;

#if (RP_HTTP_CACHE)
    {
    time_t  expires;

    if (u->conf->ignore_headers & RP_HTTP_UPSTREAM_IGN_EXPIRES) {
        return RP_OK;
    }

    if (r->cache == NULL) {
        return RP_OK;
    }

    if (r->cache->valid_sec != 0) {
        return RP_OK;
    }

    expires = rp_parse_http_time(h->value.data, h->value.len);

    if (expires == RP_ERROR || expires < rp_time()) {
        u->cacheable = 0;
        return RP_OK;
    }

    r->cache->valid_sec = expires;
    }
#endif

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_accel_expires(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset)
{
    rp_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.x_accel_expires = h;

#if (RP_HTTP_CACHE)
    {
    u_char     *p;
    size_t      len;
    rp_int_t   n;

    if (u->conf->ignore_headers & RP_HTTP_UPSTREAM_IGN_XA_EXPIRES) {
        return RP_OK;
    }

    if (r->cache == NULL) {
        return RP_OK;
    }

    len = h->value.len;
    p = h->value.data;

    if (p[0] != '@') {
        n = rp_atoi(p, len);

        switch (n) {
        case 0:
            u->cacheable = 0;
            /* fall through */

        case RP_ERROR:
            return RP_OK;

        default:
            r->cache->valid_sec = rp_time() + n;
            return RP_OK;
        }
    }

    p++;
    len--;

    n = rp_atoi(p, len);

    if (n != RP_ERROR) {
        r->cache->valid_sec = n;
    }
    }
#endif

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_limit_rate(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_int_t             n;
    rp_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.x_accel_limit_rate = h;

    if (u->conf->ignore_headers & RP_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE) {
        return RP_OK;
    }

    n = rp_atoi(h->value.data, h->value.len);

    if (n != RP_ERROR) {
        r->limit_rate = (size_t) n;
        r->limit_rate_set = 1;
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_buffering(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    u_char                c0, c1, c2;
    rp_http_upstream_t  *u;

    u = r->upstream;

    if (u->conf->ignore_headers & RP_HTTP_UPSTREAM_IGN_XA_BUFFERING) {
        return RP_OK;
    }

    if (u->conf->change_buffering) {

        if (h->value.len == 2) {
            c0 = rp_tolower(h->value.data[0]);
            c1 = rp_tolower(h->value.data[1]);

            if (c0 == 'n' && c1 == 'o') {
                u->buffering = 0;
            }

        } else if (h->value.len == 3) {
            c0 = rp_tolower(h->value.data[0]);
            c1 = rp_tolower(h->value.data[1]);
            c2 = rp_tolower(h->value.data[2]);

            if (c0 == 'y' && c1 == 'e' && c2 == 's') {
                u->buffering = 1;
            }
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_charset(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    if (r->upstream->conf->ignore_headers & RP_HTTP_UPSTREAM_IGN_XA_CHARSET) {
        return RP_OK;
    }

    r->headers_out.override_charset = &h->value;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_connection(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    r->upstream->headers_in.connection = h;

    if (rp_strlcasestrn(h->value.data, h->value.data + h->value.len,
                         (u_char *) "close", 5 - 1)
        != NULL)
    {
        r->upstream->headers_in.connection_close = 1;
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_transfer_encoding(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset)
{
    r->upstream->headers_in.transfer_encoding = h;

    if (rp_strlcasestrn(h->value.data, h->value.data + h->value.len,
                         (u_char *) "chunked", 7 - 1)
        != NULL)
    {
        r->upstream->headers_in.chunked = 1;
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_process_vary(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset)
{
    rp_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.vary = h;

#if (RP_HTTP_CACHE)

    if (u->conf->ignore_headers & RP_HTTP_UPSTREAM_IGN_VARY) {
        return RP_OK;
    }

    if (r->cache == NULL) {
        return RP_OK;
    }

    if (h->value.len > RP_HTTP_CACHE_VARY_LEN
        || (h->value.len == 1 && h->value.data[0] == '*'))
    {
        u->cacheable = 0;
    }

    r->cache->vary = h->value;

#endif

    return RP_OK;
}


static rp_int_t
rp_http_upstream_copy_header_line(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_table_elt_t  *ho, **ph;

    ho = rp_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RP_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (rp_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_copy_multi_header_lines(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset)
{
    rp_array_t      *pa;
    rp_table_elt_t  *ho, **ph;

    pa = (rp_array_t *) ((char *) &r->headers_out + offset);

    if (pa->elts == NULL) {
        if (rp_array_init(pa, r->pool, 2, sizeof(rp_table_elt_t *)) != RP_OK)
        {
            return RP_ERROR;
        }
    }

    ho = rp_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RP_ERROR;
    }

    *ho = *h;

    ph = rp_array_push(pa);
    if (ph == NULL) {
        return RP_ERROR;
    }

    *ph = ho;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_copy_content_type(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    u_char  *p, *last;

    r->headers_out.content_type_len = h->value.len;
    r->headers_out.content_type = h->value;
    r->headers_out.content_type_lowcase = NULL;

    for (p = h->value.data; *p; p++) {

        if (*p != ';') {
            continue;
        }

        last = p;

        while (*++p == ' ') { /* void */ }

        if (*p == '\0') {
            return RP_OK;
        }

        if (rp_strncasecmp(p, (u_char *) "charset=", 8) != 0) {
            continue;
        }

        p += 8;

        r->headers_out.content_type_len = last - h->value.data;

        if (*p == '"') {
            p++;
        }

        last = h->value.data + h->value.len;

        if (*(last - 1) == '"') {
            last--;
        }

        r->headers_out.charset.len = last - p;
        r->headers_out.charset.data = p;

        return RP_OK;
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_copy_last_modified(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_table_elt_t  *ho;

    ho = rp_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RP_ERROR;
    }

    *ho = *h;

    r->headers_out.last_modified = ho;
    r->headers_out.last_modified_time =
                                    r->upstream->headers_in.last_modified_time;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_rewrite_location(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_int_t         rc;
    rp_table_elt_t  *ho;

    ho = rp_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RP_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_redirect) {
        rc = r->upstream->rewrite_redirect(r, ho, 0);

        if (rc == RP_DECLINED) {
            return RP_OK;
        }

        if (rc == RP_OK) {
            r->headers_out.location = ho;

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten location: \"%V\"", &ho->value);
        }

        return rc;
    }

    if (ho->value.data[0] != '/') {
        r->headers_out.location = ho;
    }

    /*
     * we do not set r->headers_out.location here to avoid handling
     * relative redirects in rp_http_header_filter()
     */

    return RP_OK;
}


static rp_int_t
rp_http_upstream_rewrite_refresh(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    u_char           *p;
    rp_int_t         rc;
    rp_table_elt_t  *ho;

    ho = rp_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RP_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_redirect) {

        p = rp_strcasestrn(ho->value.data, "url=", 4 - 1);

        if (p) {
            rc = r->upstream->rewrite_redirect(r, ho, p + 4 - ho->value.data);

        } else {
            return RP_OK;
        }

        if (rc == RP_DECLINED) {
            return RP_OK;
        }

        if (rc == RP_OK) {
            r->headers_out.refresh = ho;

            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten refresh: \"%V\"", &ho->value);
        }

        return rc;
    }

    r->headers_out.refresh = ho;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_rewrite_set_cookie(rp_http_request_t *r, rp_table_elt_t *h,
    rp_uint_t offset)
{
    rp_int_t         rc;
    rp_table_elt_t  *ho;

    ho = rp_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RP_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_cookie) {
        rc = r->upstream->rewrite_cookie(r, ho);

        if (rc == RP_DECLINED) {
            return RP_OK;
        }

#if (RP_DEBUG)
        if (rc == RP_OK) {
            rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten cookie: \"%V\"", &ho->value);
        }
#endif

        return rc;
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_copy_allow_ranges(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset)
{
    rp_table_elt_t  *ho;

    if (r->upstream->conf->force_ranges) {
        return RP_OK;
    }

#if (RP_HTTP_CACHE)

    if (r->cached) {
        r->allow_ranges = 1;
        return RP_OK;
    }

    if (r->upstream->cacheable) {
        r->allow_ranges = 1;
        r->single_range = 1;
        return RP_OK;
    }

#endif

    ho = rp_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RP_ERROR;
    }

    *ho = *h;

    r->headers_out.accept_ranges = ho;

    return RP_OK;
}


#if (RP_HTTP_GZIP)

static rp_int_t
rp_http_upstream_copy_content_encoding(rp_http_request_t *r,
    rp_table_elt_t *h, rp_uint_t offset)
{
    rp_table_elt_t  *ho;

    ho = rp_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RP_ERROR;
    }

    *ho = *h;

    r->headers_out.content_encoding = ho;

    return RP_OK;
}

#endif


static rp_int_t
rp_http_upstream_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var, *v;

    for (v = rp_http_upstream_vars; v->name.len; v++) {
        var = rp_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_http_upstream_addr_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    rp_uint_t                  i;
    rp_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    len = 0;
    state = r->upstream_states->elts;

    for (i = 0; i < r->upstream_states->nelts; i++) {
        if (state[i].peer) {
            len += state[i].peer->len + 2;

        } else {
            len += 3;
        }
    }

    p = rp_pnalloc(r->pool, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->data = p;

    i = 0;

    for ( ;; ) {
        if (state[i].peer) {
            p = rp_cpymem(p, state[i].peer->data, state[i].peer->len);
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_status_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    rp_uint_t                  i;
    rp_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    len = r->upstream_states->nelts * (3 + 2);

    p = rp_pnalloc(r->pool, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {
        if (state[i].status) {
            p = rp_sprintf(p, "%ui", state[i].status);

        } else {
            *p++ = '-';
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_response_time_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    rp_uint_t                  i;
    rp_msec_int_t              ms;
    rp_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    len = r->upstream_states->nelts * (RP_TIME_T_LEN + 4 + 2);

    p = rp_pnalloc(r->pool, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            ms = state[i].header_time;

        } else if (data == 2) {
            ms = state[i].connect_time;

        } else {
            ms = state[i].response_time;
        }

        if (ms != -1) {
            ms = rp_max(ms, 0);
            p = rp_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

        } else {
            *p++ = '-';
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_response_length_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    rp_uint_t                  i;
    rp_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    len = r->upstream_states->nelts * (RP_OFF_T_LEN + 2);

    p = rp_pnalloc(r->pool, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            p = rp_sprintf(p, "%O", state[i].bytes_received);

        } else if (data == 2) {
            p = rp_sprintf(p, "%O", state[i].bytes_sent);

        } else {
            p = rp_sprintf(p, "%O", state[i].response_length);
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_header_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL) {
        v->not_found = 1;
        return RP_OK;
    }

    return rp_http_variable_unknown_header(v, (rp_str_t *) data,
                                         &r->upstream->headers_in.headers.part,
                                         sizeof("upstream_http_") - 1);
}


static rp_int_t
rp_http_upstream_trailer_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL) {
        v->not_found = 1;
        return RP_OK;
    }

    return rp_http_variable_unknown_header(v, (rp_str_t *) data,
                                        &r->upstream->headers_in.trailers.part,
                                        sizeof("upstream_trailer_") - 1);
}


static rp_int_t
rp_http_upstream_cookie_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_str_t  *name = (rp_str_t *) data;

    rp_str_t   cookie, s;

    if (r->upstream == NULL) {
        v->not_found = 1;
        return RP_OK;
    }

    s.len = name->len - (sizeof("upstream_cookie_") - 1);
    s.data = name->data + sizeof("upstream_cookie_") - 1;

    if (rp_http_parse_set_cookie_lines(&r->upstream->headers_in.cookies,
                                        &s, &cookie)
        == RP_DECLINED)
    {
        v->not_found = 1;
        return RP_OK;
    }

    v->len = cookie.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cookie.data;

    return RP_OK;
}


#if (RP_HTTP_CACHE)

static rp_int_t
rp_http_upstream_cache_status(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_uint_t  n;

    if (r->upstream == NULL || r->upstream->cache_status == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    n = r->upstream->cache_status - 1;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = rp_http_cache_status[n].len;
    v->data = rp_http_cache_status[n].data;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_cache_last_modified(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->upstream == NULL
        || !r->upstream->conf->cache_revalidate
        || r->upstream->cache_status != RP_HTTP_CACHE_EXPIRED
        || r->cache->last_modified == -1)
    {
        v->not_found = 1;
        return RP_OK;
    }

    p = rp_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->len = rp_http_time(p, r->cache->last_modified) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_http_upstream_cache_etag(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL
        || !r->upstream->conf->cache_revalidate
        || r->upstream->cache_status != RP_HTTP_CACHE_EXPIRED
        || r->cache->etag.len == 0)
    {
        v->not_found = 1;
        return RP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = r->cache->etag.len;
    v->data = r->cache->etag.data;

    return RP_OK;
}

#endif


static char *
rp_http_upstream(rp_conf_t *cf, rp_command_t *cmd, void *dummy)
{
    char                          *rv;
    void                          *mconf;
    rp_str_t                     *value;
    rp_url_t                      u;
    rp_uint_t                     m;
    rp_conf_t                     pcf;
    rp_http_module_t             *module;
    rp_http_conf_ctx_t           *ctx, *http_ctx;
    rp_http_upstream_srv_conf_t  *uscf;

    rp_memzero(&u, sizeof(rp_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    uscf = rp_http_upstream_add(cf, &u, RP_HTTP_UPSTREAM_CREATE
                                         |RP_HTTP_UPSTREAM_WEIGHT
                                         |RP_HTTP_UPSTREAM_MAX_CONNS
                                         |RP_HTTP_UPSTREAM_MAX_FAILS
                                         |RP_HTTP_UPSTREAM_FAIL_TIMEOUT
                                         |RP_HTTP_UPSTREAM_DOWN
                                         |RP_HTTP_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return RP_CONF_ERROR;
    }


    ctx = rp_pcalloc(cf->pool, sizeof(rp_http_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_http_max_module);
    if (ctx->srv_conf == NULL) {
        return RP_CONF_ERROR;
    }

    ctx->srv_conf[rp_http_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;


    /* the upstream{}'s loc_conf */

    ctx->loc_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RP_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return RP_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return RP_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    uscf->servers = rp_array_create(cf->pool, 4,
                                     sizeof(rp_http_upstream_server_t));
    if (uscf->servers == NULL) {
        return RP_CONF_ERROR;
    }


    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RP_HTTP_UPS_CONF;

    rv = rp_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != RP_CONF_OK) {
        return rv;
    }

    if (uscf->servers->nelts == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return RP_CONF_ERROR;
    }

    return rv;
}


static char *
rp_http_upstream_server(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_upstream_srv_conf_t  *uscf = conf;

    time_t                       fail_timeout;
    rp_str_t                   *value, s;
    rp_url_t                    u;
    rp_int_t                    weight, max_conns, max_fails;
    rp_uint_t                   i;
    rp_http_upstream_server_t  *us;

    us = rp_array_push(uscf->servers);
    if (us == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(us, sizeof(rp_http_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (rp_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & RP_HTTP_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = rp_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == RP_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "max_conns=", 10) == 0) {

            if (!(uscf->flags & RP_HTTP_UPSTREAM_MAX_CONNS)) {
                goto not_supported;
            }

            max_conns = rp_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == RP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & RP_HTTP_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = rp_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == RP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & RP_HTTP_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = rp_parse_time(&s, 1);

            if (fail_timeout == (time_t) RP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rp_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & RP_HTTP_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (rp_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & RP_HTTP_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    rp_memzero(&u, sizeof(rp_url_t));

    u.url = value[1];
    u.default_port = 80;

    if (rp_parse_url(cf->pool, &u) != RP_OK) {
        if (u.err) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return RP_CONF_ERROR;
    }

    us->name = u.url;
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_conns = max_conns;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return RP_CONF_OK;

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return RP_CONF_ERROR;

not_supported:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return RP_CONF_ERROR;
}


rp_http_upstream_srv_conf_t *
rp_http_upstream_add(rp_conf_t *cf, rp_url_t *u, rp_uint_t flags)
{
    rp_uint_t                      i;
    rp_http_upstream_server_t     *us;
    rp_http_upstream_srv_conf_t   *uscf, **uscfp;
    rp_http_upstream_main_conf_t  *umcf;

    if (!(flags & RP_HTTP_UPSTREAM_CREATE)) {

        if (rp_parse_url(cf->pool, u) != RP_OK) {
            if (u->err) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = rp_http_conf_get_module_main_conf(cf, rp_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || rp_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & RP_HTTP_UPSTREAM_CREATE)
             && (uscfp[i]->flags & RP_HTTP_UPSTREAM_CREATE))
        {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & RP_HTTP_UPSTREAM_CREATE) && !u->no_port) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & RP_HTTP_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

        if (uscfp[i]->port && u->port
            && uscfp[i]->port != u->port)
        {
            continue;
        }

        if (flags & RP_HTTP_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
            uscfp[i]->port = 0;
        }

        return uscfp[i];
    }

    uscf = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->no_port = u->no_port;

    if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
        uscf->servers = rp_array_create(cf->pool, 1,
                                         sizeof(rp_http_upstream_server_t));
        if (uscf->servers == NULL) {
            return NULL;
        }

        us = rp_array_push(uscf->servers);
        if (us == NULL) {
            return NULL;
        }

        rp_memzero(us, sizeof(rp_http_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    uscfp = rp_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


char *
rp_http_upstream_bind_set_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    rp_int_t                           rc;
    rp_str_t                          *value;
    rp_http_complex_value_t            cv;
    rp_http_upstream_local_t         **plocal, *local;
    rp_http_compile_complex_value_t    ccv;

    plocal = (rp_http_upstream_local_t **) (p + cmd->offset);

    if (*plocal != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && rp_strcmp(value[1].data, "off") == 0) {
        *plocal = NULL;
        return RP_CONF_OK;
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    local = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_local_t));
    if (local == NULL) {
        return RP_CONF_ERROR;
    }

    *plocal = local;

    if (cv.lengths) {
        local->value = rp_palloc(cf->pool, sizeof(rp_http_complex_value_t));
        if (local->value == NULL) {
            return RP_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = rp_palloc(cf->pool, sizeof(rp_addr_t));
        if (local->addr == NULL) {
            return RP_CONF_ERROR;
        }

        rc = rp_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case RP_OK:
            local->addr->name = value[1];
            break;

        case RP_DECLINED:
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return RP_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (rp_strcmp(value[2].data, "transparent") == 0) {
#if (RP_HAVE_TRANSPARENT_PROXY)
            rp_core_conf_t  *ccf;

            ccf = (rp_core_conf_t *) rp_get_conf(cf->cycle->conf_ctx,
                                                   rp_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_upstream_set_local(rp_http_request_t *r, rp_http_upstream_t *u,
    rp_http_upstream_local_t *local)
{
    rp_int_t    rc;
    rp_str_t    val;
    rp_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return RP_OK;
    }

#if (RP_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return RP_OK;
    }

    if (rp_http_complex_value(r, local->value, &val) != RP_OK) {
        return RP_ERROR;
    }

    if (val.len == 0) {
        return RP_OK;
    }

    addr = rp_palloc(r->pool, sizeof(rp_addr_t));
    if (addr == NULL) {
        return RP_ERROR;
    }

    rc = rp_parse_addr_port(r->pool, addr, val.data, val.len);
    if (rc == RP_ERROR) {
        return RP_ERROR;
    }

    if (rc != RP_OK) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return RP_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return RP_OK;
}


char *
rp_http_upstream_param_set_slot(rp_conf_t *cf, rp_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    rp_str_t                   *value;
    rp_array_t                **a;
    rp_http_upstream_param_t   *param;

    a = (rp_array_t **) (p + cmd->offset);

    if (*a == NULL) {
        *a = rp_array_create(cf->pool, 4, sizeof(rp_http_upstream_param_t));
        if (*a == NULL) {
            return RP_CONF_ERROR;
        }
    }

    param = rp_array_push(*a);
    if (param == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    param->key = value[1];
    param->value = value[2];
    param->skip_empty = 0;

    if (cf->args->nelts == 4) {
        if (rp_strcmp(value[3].data, "if_not_empty") != 0) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return RP_CONF_ERROR;
        }

        param->skip_empty = 1;
    }

    return RP_CONF_OK;
}


rp_int_t
rp_http_upstream_hide_headers_hash(rp_conf_t *cf,
    rp_http_upstream_conf_t *conf, rp_http_upstream_conf_t *prev,
    rp_str_t *default_hide_headers, rp_hash_init_t *hash)
{
    rp_str_t       *h;
    rp_uint_t       i, j;
    rp_array_t      hide_headers;
    rp_hash_key_t  *hk;

    if (conf->hide_headers == RP_CONF_UNSET_PTR
        && conf->pass_headers == RP_CONF_UNSET_PTR)
    {
        conf->hide_headers = prev->hide_headers;
        conf->pass_headers = prev->pass_headers;

        conf->hide_headers_hash = prev->hide_headers_hash;

        if (conf->hide_headers_hash.buckets) {
            return RP_OK;
        }

    } else {
        if (conf->hide_headers == RP_CONF_UNSET_PTR) {
            conf->hide_headers = prev->hide_headers;
        }

        if (conf->pass_headers == RP_CONF_UNSET_PTR) {
            conf->pass_headers = prev->pass_headers;
        }
    }

    if (rp_array_init(&hide_headers, cf->temp_pool, 4, sizeof(rp_hash_key_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    for (h = default_hide_headers; h->len; h++) {
        hk = rp_array_push(&hide_headers);
        if (hk == NULL) {
            return RP_ERROR;
        }

        hk->key = *h;
        hk->key_hash = rp_hash_key_lc(h->data, h->len);
        hk->value = (void *) 1;
    }

    if (conf->hide_headers != RP_CONF_UNSET_PTR) {

        h = conf->hide_headers->elts;

        for (i = 0; i < conf->hide_headers->nelts; i++) {

            hk = hide_headers.elts;

            for (j = 0; j < hide_headers.nelts; j++) {
                if (rp_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    goto exist;
                }
            }

            hk = rp_array_push(&hide_headers);
            if (hk == NULL) {
                return RP_ERROR;
            }

            hk->key = h[i];
            hk->key_hash = rp_hash_key_lc(h[i].data, h[i].len);
            hk->value = (void *) 1;

        exist:

            continue;
        }
    }

    if (conf->pass_headers != RP_CONF_UNSET_PTR) {

        h = conf->pass_headers->elts;
        hk = hide_headers.elts;

        for (i = 0; i < conf->pass_headers->nelts; i++) {
            for (j = 0; j < hide_headers.nelts; j++) {

                if (hk[j].key.data == NULL) {
                    continue;
                }

                if (rp_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    hk[j].key.data = NULL;
                    break;
                }
            }
        }
    }

    hash->hash = &conf->hide_headers_hash;
    hash->key = rp_hash_key_lc;
    hash->pool = cf->pool;
    hash->temp_pool = NULL;

    if (rp_hash_init(hash, hide_headers.elts, hide_headers.nelts) != RP_OK) {
        return RP_ERROR;
    }

    /*
     * special handling to preserve conf->hide_headers_hash
     * in the "http" section to inherit it to all servers
     */

    if (prev->hide_headers_hash.buckets == NULL
        && conf->hide_headers == prev->hide_headers
        && conf->pass_headers == prev->pass_headers)
    {
        prev->hide_headers_hash = conf->hide_headers_hash;
    }

    return RP_OK;
}


static void *
rp_http_upstream_create_main_conf(rp_conf_t *cf)
{
    rp_http_upstream_main_conf_t  *umcf;

    umcf = rp_pcalloc(cf->pool, sizeof(rp_http_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (rp_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(rp_http_upstream_srv_conf_t *))
        != RP_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
rp_http_upstream_init_main_conf(rp_conf_t *cf, void *conf)
{
    rp_http_upstream_main_conf_t  *umcf = conf;

    rp_uint_t                      i;
    rp_array_t                     headers_in;
    rp_hash_key_t                 *hk;
    rp_hash_init_t                 hash;
    rp_http_upstream_init_pt       init;
    rp_http_upstream_header_t     *header;
    rp_http_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream ? uscfp[i]->peer.init_upstream:
                                            rp_http_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }


    /* upstream_headers_in_hash */

    if (rp_array_init(&headers_in, cf->temp_pool, 32, sizeof(rp_hash_key_t))
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    for (header = rp_http_upstream_headers_in; header->name.len; header++) {
        hk = rp_array_push(&headers_in);
        if (hk == NULL) {
            return RP_CONF_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = rp_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &umcf->headers_in_hash;
    hash.key = rp_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = rp_align(64, rp_cacheline_size);
    hash.name = "upstream_headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (rp_hash_init(&hash, headers_in.elts, headers_in.nelts) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
