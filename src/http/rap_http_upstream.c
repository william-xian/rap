
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#if (RAP_HTTP_CACHE)
static rap_int_t rap_http_upstream_cache(rap_http_request_t *r,
    rap_http_upstream_t *u);
static rap_int_t rap_http_upstream_cache_get(rap_http_request_t *r,
    rap_http_upstream_t *u, rap_http_file_cache_t **cache);
static rap_int_t rap_http_upstream_cache_send(rap_http_request_t *r,
    rap_http_upstream_t *u);
static rap_int_t rap_http_upstream_cache_background_update(
    rap_http_request_t *r, rap_http_upstream_t *u);
static rap_int_t rap_http_upstream_cache_check_range(rap_http_request_t *r,
    rap_http_upstream_t *u);
static rap_int_t rap_http_upstream_cache_status(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_upstream_cache_last_modified(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_upstream_cache_etag(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
#endif

static void rap_http_upstream_init_request(rap_http_request_t *r);
static void rap_http_upstream_resolve_handler(rap_resolver_ctx_t *ctx);
static void rap_http_upstream_rd_check_broken_connection(rap_http_request_t *r);
static void rap_http_upstream_wr_check_broken_connection(rap_http_request_t *r);
static void rap_http_upstream_check_broken_connection(rap_http_request_t *r,
    rap_event_t *ev);
static void rap_http_upstream_connect(rap_http_request_t *r,
    rap_http_upstream_t *u);
static rap_int_t rap_http_upstream_reinit(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_send_request(rap_http_request_t *r,
    rap_http_upstream_t *u, rap_uint_t do_write);
static rap_int_t rap_http_upstream_send_request_body(rap_http_request_t *r,
    rap_http_upstream_t *u, rap_uint_t do_write);
static void rap_http_upstream_send_request_handler(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_read_request_handler(rap_http_request_t *r);
static void rap_http_upstream_process_header(rap_http_request_t *r,
    rap_http_upstream_t *u);
static rap_int_t rap_http_upstream_test_next(rap_http_request_t *r,
    rap_http_upstream_t *u);
static rap_int_t rap_http_upstream_intercept_errors(rap_http_request_t *r,
    rap_http_upstream_t *u);
static rap_int_t rap_http_upstream_test_connect(rap_connection_t *c);
static rap_int_t rap_http_upstream_process_headers(rap_http_request_t *r,
    rap_http_upstream_t *u);
static rap_int_t rap_http_upstream_process_trailers(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_send_response(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_upgrade(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_upgraded_read_downstream(rap_http_request_t *r);
static void rap_http_upstream_upgraded_write_downstream(rap_http_request_t *r);
static void rap_http_upstream_upgraded_read_upstream(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_upgraded_write_upstream(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_process_upgraded(rap_http_request_t *r,
    rap_uint_t from_upstream, rap_uint_t do_write);
static void
    rap_http_upstream_process_non_buffered_downstream(rap_http_request_t *r);
static void
    rap_http_upstream_process_non_buffered_upstream(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void
    rap_http_upstream_process_non_buffered_request(rap_http_request_t *r,
    rap_uint_t do_write);
static rap_int_t rap_http_upstream_non_buffered_filter_init(void *data);
static rap_int_t rap_http_upstream_non_buffered_filter(void *data,
    ssize_t bytes);
#if (RAP_THREADS)
static rap_int_t rap_http_upstream_thread_handler(rap_thread_task_t *task,
    rap_file_t *file);
static void rap_http_upstream_thread_event_handler(rap_event_t *ev);
#endif
static rap_int_t rap_http_upstream_output_filter(void *data,
    rap_chain_t *chain);
static void rap_http_upstream_process_downstream(rap_http_request_t *r);
static void rap_http_upstream_process_upstream(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_process_request(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_store(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_dummy_handler(rap_http_request_t *r,
    rap_http_upstream_t *u);
static void rap_http_upstream_next(rap_http_request_t *r,
    rap_http_upstream_t *u, rap_uint_t ft_type);
static void rap_http_upstream_cleanup(void *data);
static void rap_http_upstream_finalize_request(rap_http_request_t *r,
    rap_http_upstream_t *u, rap_int_t rc);

static rap_int_t rap_http_upstream_process_header_line(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_content_length(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_last_modified(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_set_cookie(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t
    rap_http_upstream_process_cache_control(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_ignore_header_line(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_expires(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_accel_expires(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_limit_rate(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_buffering(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_charset(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_connection(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t
    rap_http_upstream_process_transfer_encoding(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_process_vary(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_copy_header_line(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t
    rap_http_upstream_copy_multi_header_lines(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_copy_content_type(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_copy_last_modified(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_rewrite_location(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_rewrite_refresh(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_rewrite_set_cookie(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
static rap_int_t rap_http_upstream_copy_allow_ranges(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);

#if (RAP_HTTP_GZIP)
static rap_int_t rap_http_upstream_copy_content_encoding(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset);
#endif

static rap_int_t rap_http_upstream_add_variables(rap_conf_t *cf);
static rap_int_t rap_http_upstream_addr_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_upstream_status_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_upstream_response_time_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_upstream_response_length_variable(
    rap_http_request_t *r, rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_upstream_header_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_upstream_trailer_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_upstream_cookie_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);

static char *rap_http_upstream(rap_conf_t *cf, rap_command_t *cmd, void *dummy);
static char *rap_http_upstream_server(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);

static rap_int_t rap_http_upstream_set_local(rap_http_request_t *r,
  rap_http_upstream_t *u, rap_http_upstream_local_t *local);

static void *rap_http_upstream_create_main_conf(rap_conf_t *cf);
static char *rap_http_upstream_init_main_conf(rap_conf_t *cf, void *conf);

#if (RAP_HTTP_SSL)
static void rap_http_upstream_ssl_init_connection(rap_http_request_t *,
    rap_http_upstream_t *u, rap_connection_t *c);
static void rap_http_upstream_ssl_handshake_handler(rap_connection_t *c);
static void rap_http_upstream_ssl_handshake(rap_http_request_t *,
    rap_http_upstream_t *u, rap_connection_t *c);
static void rap_http_upstream_ssl_save_session(rap_connection_t *c);
static rap_int_t rap_http_upstream_ssl_name(rap_http_request_t *r,
    rap_http_upstream_t *u, rap_connection_t *c);
#endif


static rap_http_upstream_header_t  rap_http_upstream_headers_in[] = {

    { rap_string("Status"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, status),
                 rap_http_upstream_copy_header_line, 0, 0 },

    { rap_string("Content-Type"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, content_type),
                 rap_http_upstream_copy_content_type, 0, 1 },

    { rap_string("Content-Length"),
                 rap_http_upstream_process_content_length, 0,
                 rap_http_upstream_ignore_header_line, 0, 0 },

    { rap_string("Date"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, date),
                 rap_http_upstream_copy_header_line,
                 offsetof(rap_http_headers_out_t, date), 0 },

    { rap_string("Last-Modified"),
                 rap_http_upstream_process_last_modified, 0,
                 rap_http_upstream_copy_last_modified, 0, 0 },

    { rap_string("ETag"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, etag),
                 rap_http_upstream_copy_header_line,
                 offsetof(rap_http_headers_out_t, etag), 0 },

    { rap_string("Server"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, server),
                 rap_http_upstream_copy_header_line,
                 offsetof(rap_http_headers_out_t, server), 0 },

    { rap_string("WWW-Authenticate"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, www_authenticate),
                 rap_http_upstream_copy_header_line, 0, 0 },

    { rap_string("Location"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, location),
                 rap_http_upstream_rewrite_location, 0, 0 },

    { rap_string("Refresh"),
                 rap_http_upstream_ignore_header_line, 0,
                 rap_http_upstream_rewrite_refresh, 0, 0 },

    { rap_string("Set-Cookie"),
                 rap_http_upstream_process_set_cookie,
                 offsetof(rap_http_upstream_headers_in_t, cookies),
                 rap_http_upstream_rewrite_set_cookie, 0, 1 },

    { rap_string("Content-Disposition"),
                 rap_http_upstream_ignore_header_line, 0,
                 rap_http_upstream_copy_header_line, 0, 1 },

    { rap_string("Cache-Control"),
                 rap_http_upstream_process_cache_control, 0,
                 rap_http_upstream_copy_multi_header_lines,
                 offsetof(rap_http_headers_out_t, cache_control), 1 },

    { rap_string("Expires"),
                 rap_http_upstream_process_expires, 0,
                 rap_http_upstream_copy_header_line,
                 offsetof(rap_http_headers_out_t, expires), 1 },

    { rap_string("Accept-Ranges"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, accept_ranges),
                 rap_http_upstream_copy_allow_ranges,
                 offsetof(rap_http_headers_out_t, accept_ranges), 1 },

    { rap_string("Content-Range"),
                 rap_http_upstream_ignore_header_line, 0,
                 rap_http_upstream_copy_header_line,
                 offsetof(rap_http_headers_out_t, content_range), 0 },

    { rap_string("Connection"),
                 rap_http_upstream_process_connection, 0,
                 rap_http_upstream_ignore_header_line, 0, 0 },

    { rap_string("Keep-Alive"),
                 rap_http_upstream_ignore_header_line, 0,
                 rap_http_upstream_ignore_header_line, 0, 0 },

    { rap_string("Vary"),
                 rap_http_upstream_process_vary, 0,
                 rap_http_upstream_copy_header_line, 0, 0 },

    { rap_string("Link"),
                 rap_http_upstream_ignore_header_line, 0,
                 rap_http_upstream_copy_multi_header_lines,
                 offsetof(rap_http_headers_out_t, link), 0 },

    { rap_string("X-Accel-Expires"),
                 rap_http_upstream_process_accel_expires, 0,
                 rap_http_upstream_copy_header_line, 0, 0 },

    { rap_string("X-Accel-Redirect"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, x_accel_redirect),
                 rap_http_upstream_copy_header_line, 0, 0 },

    { rap_string("X-Accel-Limit-Rate"),
                 rap_http_upstream_process_limit_rate, 0,
                 rap_http_upstream_copy_header_line, 0, 0 },

    { rap_string("X-Accel-Buffering"),
                 rap_http_upstream_process_buffering, 0,
                 rap_http_upstream_copy_header_line, 0, 0 },

    { rap_string("X-Accel-Charset"),
                 rap_http_upstream_process_charset, 0,
                 rap_http_upstream_copy_header_line, 0, 0 },

    { rap_string("Transfer-Encoding"),
                 rap_http_upstream_process_transfer_encoding, 0,
                 rap_http_upstream_ignore_header_line, 0, 0 },

#if (RAP_HTTP_GZIP)
    { rap_string("Content-Encoding"),
                 rap_http_upstream_process_header_line,
                 offsetof(rap_http_upstream_headers_in_t, content_encoding),
                 rap_http_upstream_copy_content_encoding, 0, 0 },
#endif

    { rap_null_string, NULL, 0, NULL, 0, 0 }
};


static rap_command_t  rap_http_upstream_commands[] = {

    { rap_string("upstream"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_TAKE1,
      rap_http_upstream,
      0,
      0,
      NULL },

    { rap_string("server"),
      RAP_HTTP_UPS_CONF|RAP_CONF_1MORE,
      rap_http_upstream_server,
      RAP_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_upstream_module_ctx = {
    rap_http_upstream_add_variables,       /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_http_upstream_create_main_conf,    /* create main configuration */
    rap_http_upstream_init_main_conf,      /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_upstream_module = {
    RAP_MODULE_V1,
    &rap_http_upstream_module_ctx,         /* module context */
    rap_http_upstream_commands,            /* module directives */
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


static rap_http_variable_t  rap_http_upstream_vars[] = {

    { rap_string("upstream_addr"), NULL,
      rap_http_upstream_addr_variable, 0,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_status"), NULL,
      rap_http_upstream_status_variable, 0,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_connect_time"), NULL,
      rap_http_upstream_response_time_variable, 2,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_header_time"), NULL,
      rap_http_upstream_response_time_variable, 1,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_response_time"), NULL,
      rap_http_upstream_response_time_variable, 0,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_response_length"), NULL,
      rap_http_upstream_response_length_variable, 0,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_bytes_received"), NULL,
      rap_http_upstream_response_length_variable, 1,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_bytes_sent"), NULL,
      rap_http_upstream_response_length_variable, 2,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

#if (RAP_HTTP_CACHE)

    { rap_string("upstream_cache_status"), NULL,
      rap_http_upstream_cache_status, 0,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_cache_last_modified"), NULL,
      rap_http_upstream_cache_last_modified, 0,
      RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_NOHASH, 0 },

    { rap_string("upstream_cache_etag"), NULL,
      rap_http_upstream_cache_etag, 0,
      RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_NOHASH, 0 },

#endif

    { rap_string("upstream_http_"), NULL, rap_http_upstream_header_variable,
      0, RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_PREFIX, 0 },

    { rap_string("upstream_trailer_"), NULL, rap_http_upstream_trailer_variable,
      0, RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_PREFIX, 0 },

    { rap_string("upstream_cookie_"), NULL, rap_http_upstream_cookie_variable,
      0, RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_PREFIX, 0 },

      rap_http_null_variable
};


static rap_http_upstream_next_t  rap_http_upstream_next_errors[] = {
    { 500, RAP_HTTP_UPSTREAM_FT_HTTP_500 },
    { 502, RAP_HTTP_UPSTREAM_FT_HTTP_502 },
    { 503, RAP_HTTP_UPSTREAM_FT_HTTP_503 },
    { 504, RAP_HTTP_UPSTREAM_FT_HTTP_504 },
    { 403, RAP_HTTP_UPSTREAM_FT_HTTP_403 },
    { 404, RAP_HTTP_UPSTREAM_FT_HTTP_404 },
    { 429, RAP_HTTP_UPSTREAM_FT_HTTP_429 },
    { 0, 0 }
};


rap_conf_bitmask_t  rap_http_upstream_cache_method_mask[] = {
    { rap_string("GET"), RAP_HTTP_GET },
    { rap_string("HEAD"), RAP_HTTP_HEAD },
    { rap_string("POST"), RAP_HTTP_POST },
    { rap_null_string, 0 }
};


rap_conf_bitmask_t  rap_http_upstream_ignore_headers_masks[] = {
    { rap_string("X-Accel-Redirect"), RAP_HTTP_UPSTREAM_IGN_XA_REDIRECT },
    { rap_string("X-Accel-Expires"), RAP_HTTP_UPSTREAM_IGN_XA_EXPIRES },
    { rap_string("X-Accel-Limit-Rate"), RAP_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE },
    { rap_string("X-Accel-Buffering"), RAP_HTTP_UPSTREAM_IGN_XA_BUFFERING },
    { rap_string("X-Accel-Charset"), RAP_HTTP_UPSTREAM_IGN_XA_CHARSET },
    { rap_string("Expires"), RAP_HTTP_UPSTREAM_IGN_EXPIRES },
    { rap_string("Cache-Control"), RAP_HTTP_UPSTREAM_IGN_CACHE_CONTROL },
    { rap_string("Set-Cookie"), RAP_HTTP_UPSTREAM_IGN_SET_COOKIE },
    { rap_string("Vary"), RAP_HTTP_UPSTREAM_IGN_VARY },
    { rap_null_string, 0 }
};


rap_int_t
rap_http_upstream_create(rap_http_request_t *r)
{
    rap_http_upstream_t  *u;

    u = r->upstream;

    if (u && u->cleanup) {
        r->main->count++;
        rap_http_upstream_cleanup(r);
    }

    u = rap_pcalloc(r->pool, sizeof(rap_http_upstream_t));
    if (u == NULL) {
        return RAP_ERROR;
    }

    r->upstream = u;

    u->peer.log = r->connection->log;
    u->peer.log_error = RAP_ERROR_ERR;

#if (RAP_HTTP_CACHE)
    r->cache = NULL;
#endif

    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    return RAP_OK;
}


void
rap_http_upstream_init(rap_http_request_t *r)
{
    rap_connection_t     *c;

    c = r->connection;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http init upstream, client timer: %d", c->read->timer_set);

#if (RAP_HTTP_V2)
    if (r->stream) {
        rap_http_upstream_init_request(r);
        return;
    }
#endif

    if (c->read->timer_set) {
        rap_del_timer(c->read);
    }

    if (rap_event_flags & RAP_USE_CLEAR_EVENT) {

        if (!c->write->active) {
            if (rap_add_event(c->write, RAP_WRITE_EVENT, RAP_CLEAR_EVENT)
                == RAP_ERROR)
            {
                rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }

    rap_http_upstream_init_request(r);
}


static void
rap_http_upstream_init_request(rap_http_request_t *r)
{
    rap_str_t                      *host;
    rap_uint_t                      i;
    rap_resolver_ctx_t             *ctx, temp;
    rap_http_cleanup_t             *cln;
    rap_http_upstream_t            *u;
    rap_http_core_loc_conf_t       *clcf;
    rap_http_upstream_srv_conf_t   *uscf, **uscfp;
    rap_http_upstream_main_conf_t  *umcf;

    if (r->aio) {
        return;
    }

    u = r->upstream;

#if (RAP_HTTP_CACHE)

    if (u->conf->cache) {
        rap_int_t  rc;

        rc = rap_http_upstream_cache(r, u);

        if (rc == RAP_BUSY) {
            r->write_event_handler = rap_http_upstream_init_request;
            return;
        }

        r->write_event_handler = rap_http_request_empty_handler;

        if (rc == RAP_ERROR) {
            rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rc == RAP_OK) {
            rc = rap_http_upstream_cache_send(r, u);

            if (rc == RAP_DONE) {
                return;
            }

            if (rc == RAP_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = RAP_DECLINED;
                r->cached = 0;
                u->buffer.start = NULL;
                u->cache_status = RAP_HTTP_CACHE_MISS;
                u->request_sent = 1;
            }
        }

        if (rc != RAP_DECLINED) {
            rap_http_finalize_request(r, rc);
            return;
        }
    }

#endif

    u->store = u->conf->store;

    if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
        r->read_event_handler = rap_http_upstream_rd_check_broken_connection;
        r->write_event_handler = rap_http_upstream_wr_check_broken_connection;
    }

    if (r->request_body) {
        u->request_bufs = r->request_body->bufs;
    }

    if (u->create_request(r) != RAP_OK) {
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (rap_http_upstream_set_local(r, u, u->conf->local) != RAP_OK) {
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (u->conf->socket_keepalive) {
        u->peer.so_keepalive = 1;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    u->output.alignment = clcf->directio_alignment;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;

    if (u->output.output_filter == NULL) {
        u->output.output_filter = rap_chain_writer;
        u->output.filter_ctx = &u->writer;
    }

    u->writer.pool = r->pool;

    if (r->upstream_states == NULL) {

        r->upstream_states = rap_array_create(r->pool, 1,
                                            sizeof(rap_http_upstream_state_t));
        if (r->upstream_states == NULL) {
            rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

    } else {

        u->state = rap_array_push(r->upstream_states);
        if (u->state == NULL) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        rap_memzero(u->state, sizeof(rap_http_upstream_state_t));
    }

    cln = rap_http_cleanup_add(r, 0);
    if (cln == NULL) {
        rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = rap_http_upstream_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;

    if (u->resolved == NULL) {

        uscf = u->conf->upstream;

    } else {

#if (RAP_HTTP_SSL)
        u->ssl_name = u->resolved->host;
#endif

        host = &u->resolved->host;

        umcf = rap_http_get_module_main_conf(r, rap_http_upstream_module);

        uscfp = umcf->upstreams.elts;

        for (i = 0; i < umcf->upstreams.nelts; i++) {

            uscf = uscfp[i];

            if (uscf->host.len == host->len
                && ((uscf->port == 0 && u->resolved->no_port)
                     || uscf->port == u->resolved->port)
                && rap_strncasecmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }

        if (u->resolved->sockaddr) {

            if (u->resolved->port == 0
                && u->resolved->sockaddr->sa_family != AF_UNIX)
            {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "no port in upstream \"%V\"", host);
                rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            if (rap_http_upstream_create_round_robin_peer(r, u->resolved)
                != RAP_OK)
            {
                rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            rap_http_upstream_connect(r, u);

            return;
        }

        if (u->resolved->port == 0) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "no port in upstream \"%V\"", host);
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        temp.name = *host;

        ctx = rap_resolve_start(clcf->resolver, &temp);
        if (ctx == NULL) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (ctx == RAP_NO_RESOLVER) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "no resolver defined to resolve %V", host);

            rap_http_upstream_finalize_request(r, u, RAP_HTTP_BAD_GATEWAY);
            return;
        }

        ctx->name = *host;
        ctx->handler = rap_http_upstream_resolve_handler;
        ctx->data = r;
        ctx->timeout = clcf->resolver_timeout;

        u->resolved->ctx = ctx;

        if (rap_resolve_name(ctx) != RAP_OK) {
            u->resolved->ctx = NULL;
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        return;
    }

found:

    if (uscf == NULL) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "no upstream configuration");
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->upstream = uscf;

#if (RAP_HTTP_SSL)
    u->ssl_name = uscf->host;
#endif

    if (uscf->peer.init(r, uscf) != RAP_OK) {
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->peer.start_time = rap_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    rap_http_upstream_connect(r, u);
}


#if (RAP_HTTP_CACHE)

static rap_int_t
rap_http_upstream_cache(rap_http_request_t *r, rap_http_upstream_t *u)
{
    rap_int_t               rc;
    rap_http_cache_t       *c;
    rap_http_file_cache_t  *cache;

    c = r->cache;

    if (c == NULL) {

        if (!(r->method & u->conf->cache_methods)) {
            return RAP_DECLINED;
        }

        rc = rap_http_upstream_cache_get(r, u, &cache);

        if (rc != RAP_OK) {
            return rc;
        }

        if (r->method == RAP_HTTP_HEAD && u->conf->cache_convert_head) {
            u->method = rap_http_core_get_method;
        }

        if (rap_http_file_cache_new(r) != RAP_OK) {
            return RAP_ERROR;
        }

        if (u->create_key(r) != RAP_OK) {
            return RAP_ERROR;
        }

        /* TODO: add keys */

        rap_http_file_cache_create_key(r);

        if (r->cache->header_start + 256 > u->conf->buffer_size) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "%V_buffer_size %uz is not enough for cache key, "
                          "it should be increased to at least %uz",
                          &u->conf->module, u->conf->buffer_size,
                          rap_align(r->cache->header_start + 256, 1024));

            r->cache = NULL;
            return RAP_DECLINED;
        }

        u->cacheable = 1;

        c = r->cache;

        c->body_start = u->conf->buffer_size;
        c->min_uses = u->conf->cache_min_uses;
        c->file_cache = cache;

        switch (rap_http_test_predicates(r, u->conf->cache_bypass)) {

        case RAP_ERROR:
            return RAP_ERROR;

        case RAP_DECLINED:
            u->cache_status = RAP_HTTP_CACHE_BYPASS;
            return RAP_DECLINED;

        default: /* RAP_OK */
            break;
        }

        c->lock = u->conf->cache_lock;
        c->lock_timeout = u->conf->cache_lock_timeout;
        c->lock_age = u->conf->cache_lock_age;

        u->cache_status = RAP_HTTP_CACHE_MISS;
    }

    rc = rap_http_file_cache_open(r);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream cache: %i", rc);

    switch (rc) {

    case RAP_HTTP_CACHE_STALE:

        if (((u->conf->cache_use_stale & RAP_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background
            && u->conf->cache_background_update)
        {
            if (rap_http_upstream_cache_background_update(r, u) == RAP_OK) {
                r->cache->background = 1;
                u->cache_status = rc;
                rc = RAP_OK;

            } else {
                rc = RAP_ERROR;
            }
        }

        break;

    case RAP_HTTP_CACHE_UPDATING:

        if (((u->conf->cache_use_stale & RAP_HTTP_UPSTREAM_FT_UPDATING)
             || c->stale_updating) && !r->background)
        {
            u->cache_status = rc;
            rc = RAP_OK;

        } else {
            rc = RAP_HTTP_CACHE_STALE;
        }

        break;

    case RAP_OK:
        u->cache_status = RAP_HTTP_CACHE_HIT;
    }

    switch (rc) {

    case RAP_OK:

        return RAP_OK;

    case RAP_HTTP_CACHE_STALE:

        c->valid_sec = 0;
        c->updating_sec = 0;
        c->error_sec = 0;

        u->buffer.start = NULL;
        u->cache_status = RAP_HTTP_CACHE_EXPIRED;

        break;

    case RAP_DECLINED:

        if ((size_t) (u->buffer.end - u->buffer.start) < u->conf->buffer_size) {
            u->buffer.start = NULL;

        } else {
            u->buffer.pos = u->buffer.start + c->header_start;
            u->buffer.last = u->buffer.pos;
        }

        break;

    case RAP_HTTP_CACHE_SCARCE:

        u->cacheable = 0;

        break;

    case RAP_AGAIN:

        return RAP_BUSY;

    case RAP_ERROR:

        return RAP_ERROR;

    default:

        /* cached RAP_HTTP_BAD_GATEWAY, RAP_HTTP_GATEWAY_TIME_OUT, etc. */

        u->cache_status = RAP_HTTP_CACHE_HIT;

        return rc;
    }

    if (rap_http_upstream_cache_check_range(r, u) == RAP_DECLINED) {
        u->cacheable = 0;
    }

    r->cached = 0;

    return RAP_DECLINED;
}


static rap_int_t
rap_http_upstream_cache_get(rap_http_request_t *r, rap_http_upstream_t *u,
    rap_http_file_cache_t **cache)
{
    rap_str_t               *name, val;
    rap_uint_t               i;
    rap_http_file_cache_t  **caches;

    if (u->conf->cache_zone) {
        *cache = u->conf->cache_zone->data;
        return RAP_OK;
    }

    if (rap_http_complex_value(r, u->conf->cache_value, &val) != RAP_OK) {
        return RAP_ERROR;
    }

    if (val.len == 0
        || (val.len == 3 && rap_strncmp(val.data, "off", 3) == 0))
    {
        return RAP_DECLINED;
    }

    caches = u->caches->elts;

    for (i = 0; i < u->caches->nelts; i++) {
        name = &caches[i]->shm_zone->shm.name;

        if (name->len == val.len
            && rap_strncmp(name->data, val.data, val.len) == 0)
        {
            *cache = caches[i];
            return RAP_OK;
        }
    }

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                  "cache \"%V\" not found", &val);

    return RAP_ERROR;
}


static rap_int_t
rap_http_upstream_cache_send(rap_http_request_t *r, rap_http_upstream_t *u)
{
    rap_int_t          rc;
    rap_http_cache_t  *c;

    r->cached = 1;
    c = r->cache;

    if (c->header_start == c->body_start) {
        r->http_version = RAP_HTTP_VERSION_9;
        return rap_http_cache_send(r);
    }

    /* TODO: cache stack */

    u->buffer = *c->buf;
    u->buffer.pos += c->header_start;

    rap_memzero(&u->headers_in, sizeof(rap_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (rap_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(rap_table_elt_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (rap_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(rap_table_elt_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    rc = u->process_header(r);

    if (rc == RAP_OK) {

        if (rap_http_upstream_process_headers(r, u) != RAP_OK) {
            return RAP_DONE;
        }

        return rap_http_cache_send(r);
    }

    if (rc == RAP_ERROR) {
        return RAP_ERROR;
    }

    if (rc == RAP_AGAIN) {
        rc = RAP_HTTP_UPSTREAM_INVALID_HEADER;
    }

    /* rc == RAP_HTTP_UPSTREAM_INVALID_HEADER */

    rap_log_error(RAP_LOG_CRIT, r->connection->log, 0,
                  "cache file \"%s\" contains invalid header",
                  c->file.name.data);

    /* TODO: delete file */

    return rc;
}


static rap_int_t
rap_http_upstream_cache_background_update(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    rap_http_request_t  *sr;

    if (r == r->main) {
        r->preserve_body = 1;
    }

    if (rap_http_subrequest(r, &r->uri, &r->args, &sr, NULL,
                            RAP_HTTP_SUBREQUEST_CLONE
                            |RAP_HTTP_SUBREQUEST_BACKGROUND)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    sr->header_only = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_cache_check_range(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    off_t             offset;
    u_char           *p, *start;
    rap_table_elt_t  *h;

    h = r->headers_in.range;

    if (h == NULL
        || !u->cacheable
        || u->conf->cache_max_range_offset == RAP_MAX_OFF_T_VALUE)
    {
        return RAP_OK;
    }

    if (u->conf->cache_max_range_offset == 0) {
        return RAP_DECLINED;
    }

    if (h->value.len < 7
        || rap_strncasecmp(h->value.data, (u_char *) "bytes=", 6) != 0)
    {
        return RAP_OK;
    }

    p = h->value.data + 6;

    while (*p == ' ') { p++; }

    if (*p == '-') {
        return RAP_DECLINED;
    }

    start = p;

    while (*p >= '0' && *p <= '9') { p++; }

    offset = rap_atoof(start, p - start);

    if (offset >= u->conf->cache_max_range_offset) {
        return RAP_DECLINED;
    }

    return RAP_OK;
}

#endif


static void
rap_http_upstream_resolve_handler(rap_resolver_ctx_t *ctx)
{
    rap_uint_t                     run_posted;
    rap_connection_t              *c;
    rap_http_request_t            *r;
    rap_http_upstream_t           *u;
    rap_http_upstream_resolved_t  *ur;

    run_posted = ctx->async;

    r = ctx->data;
    c = r->connection;

    u = r->upstream;
    ur = u->resolved;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream resolve: \"%V?%V\"", &r->uri, &r->args);

    if (ctx->state) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      rap_resolver_strerror(ctx->state));

        rap_http_upstream_finalize_request(r, u, RAP_HTTP_BAD_GATEWAY);
        goto failed;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (RAP_DEBUG)
    {
    u_char      text[RAP_SOCKADDR_STRLEN];
    rap_str_t   addr;
    rap_uint_t  i;

    addr.data = text;

    for (i = 0; i < ctx->naddrs; i++) {
        addr.len = rap_sock_ntop(ur->addrs[i].sockaddr, ur->addrs[i].socklen,
                                 text, RAP_SOCKADDR_STRLEN, 0);

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "name was resolved to %V", &addr);
    }
    }
#endif

    if (rap_http_upstream_create_round_robin_peer(r, ur) != RAP_OK) {
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_INTERNAL_SERVER_ERROR);
        goto failed;
    }

    rap_resolve_name_done(ctx);
    ur->ctx = NULL;

    u->peer.start_time = rap_current_msec;

    if (u->conf->next_upstream_tries
        && u->peer.tries > u->conf->next_upstream_tries)
    {
        u->peer.tries = u->conf->next_upstream_tries;
    }

    rap_http_upstream_connect(r, u);

failed:

    if (run_posted) {
        rap_http_run_posted_requests(c);
    }
}


static void
rap_http_upstream_handler(rap_event_t *ev)
{
    rap_connection_t     *c;
    rap_http_request_t   *r;
    rap_http_upstream_t  *u;

    c = ev->data;
    r = c->data;

    u = r->upstream;
    c = r->connection;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
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

    rap_http_run_posted_requests(c);
}


static void
rap_http_upstream_rd_check_broken_connection(rap_http_request_t *r)
{
    rap_http_upstream_check_broken_connection(r, r->connection->read);
}


static void
rap_http_upstream_wr_check_broken_connection(rap_http_request_t *r)
{
    rap_http_upstream_check_broken_connection(r, r->connection->write);
}


static void
rap_http_upstream_check_broken_connection(rap_http_request_t *r,
    rap_event_t *ev)
{
    int                  n;
    char                 buf[1];
    rap_err_t            err;
    rap_int_t            event;
    rap_connection_t     *c;
    rap_http_upstream_t  *u;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, ev->log, 0,
                   "http upstream check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;
    u = r->upstream;

    if (c->error) {
        if ((rap_event_flags & RAP_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? RAP_WRITE_EVENT : RAP_READ_EVENT;

            if (rap_del_event(ev, event, 0) != RAP_OK) {
                rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        if (!u->cacheable) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#if (RAP_HTTP_V2)
    if (r->stream) {
        return;
    }
#endif

#if (RAP_HAVE_KQUEUE)

    if (rap_event_flags & RAP_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            rap_log_error(RAP_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client prematurely closed "
                          "connection, so upstream connection is closed too");
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        rap_log_error(RAP_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

#if (RAP_HAVE_EPOLLRDHUP)

    if ((rap_event_flags & RAP_USE_EPOLL_EVENT) && rap_use_epoll_rdhup) {
        socklen_t  len;

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        err = 0;
        len = sizeof(rap_err_t);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = rap_socket_errno;
        }

        if (err) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            rap_log_error(RAP_LOG_INFO, ev->log, err,
                        "epoll_wait() reported that client prematurely closed "
                        "connection, so upstream connection is closed too");
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        rap_log_error(RAP_LOG_INFO, ev->log, err,
                      "epoll_wait() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = rap_socket_errno;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, ev->log, err,
                   "http upstream recv(): %d", n);

    if (ev->write && (n >= 0 || err == RAP_EAGAIN)) {
        return;
    }

    if ((rap_event_flags & RAP_USE_LEVEL_EVENT) && ev->active) {

        event = ev->write ? RAP_WRITE_EVENT : RAP_READ_EVENT;

        if (rap_del_event(ev, event, 0) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == RAP_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (!u->cacheable && u->peer.connection) {
        rap_log_error(RAP_LOG_INFO, ev->log, err,
                      "client prematurely closed connection, "
                      "so upstream connection is closed too");
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    rap_log_error(RAP_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    if (u->peer.connection == NULL) {
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_CLIENT_CLOSED_REQUEST);
    }
}


static void
rap_http_upstream_connect(rap_http_request_t *r, rap_http_upstream_t *u)
{
    rap_int_t          rc;
    rap_connection_t  *c;

    r->connection->log->action = "connecting to upstream";

    if (u->state && u->state->response_time == (rap_msec_t) -1) {
        u->state->response_time = rap_current_msec - u->start_time;
    }

    u->state = rap_array_push(r->upstream_states);
    if (u->state == NULL) {
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    rap_memzero(u->state, sizeof(rap_http_upstream_state_t));

    u->start_time = rap_current_msec;

    u->state->response_time = (rap_msec_t) -1;
    u->state->connect_time = (rap_msec_t) -1;
    u->state->header_time = (rap_msec_t) -1;

    rc = rap_event_connect_peer(&u->peer);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream connect: %i", rc);

    if (rc == RAP_ERROR) {
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    u->state->peer = u->peer.name;

    if (rc == RAP_BUSY) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0, "no live upstreams");
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_NOLIVE);
        return;
    }

    if (rc == RAP_DECLINED) {
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    /* rc == RAP_OK || rc == RAP_AGAIN || rc == RAP_DONE */

    c = u->peer.connection;

    c->requests++;

    c->data = r;

    c->write->handler = rap_http_upstream_handler;
    c->read->handler = rap_http_upstream_handler;

    u->write_event_handler = rap_http_upstream_send_request_handler;
    u->read_event_handler = rap_http_upstream_process_header;

    c->sendfile &= r->connection->sendfile;
    u->output.sendfile = c->sendfile;

    if (r->connection->tcp_nopush == RAP_TCP_NOPUSH_DISABLED) {
        c->tcp_nopush = RAP_TCP_NOPUSH_DISABLED;
    }

    if (c->pool == NULL) {

        /* we need separate pool here to be able to cache SSL connections */

        c->pool = rap_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;

    /* init or reinit the rap_output_chain() and rap_chain_writer() contexts */

    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit = 0;

    if (u->request_sent) {
        if (rap_http_upstream_reinit(r, u) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
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

        u->output.free = rap_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
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

    if (rc == RAP_AGAIN) {
        rap_add_timer(c->write, u->conf->connect_timeout);
        return;
    }

#if (RAP_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        rap_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    rap_http_upstream_send_request(r, u, 1);
}


#if (RAP_HTTP_SSL)

static void
rap_http_upstream_ssl_init_connection(rap_http_request_t *r,
    rap_http_upstream_t *u, rap_connection_t *c)
{
    rap_int_t                  rc;
    rap_http_core_loc_conf_t  *clcf;

    if (rap_http_upstream_test_connect(c) != RAP_OK) {
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (rap_ssl_create_connection(u->conf->ssl, c,
                                  RAP_SSL_BUFFER|RAP_SSL_CLIENT)
        != RAP_OK)
    {
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    c->sendfile = 0;
    u->output.sendfile = 0;

    if (u->conf->ssl_server_name || u->conf->ssl_verify) {
        if (rap_http_upstream_ssl_name(r, u, c) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (u->conf->ssl_session_reuse) {
        c->ssl->save_session = rap_http_upstream_ssl_save_session;

        if (u->peer.set_session(&u->peer, u->peer.data) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        /* abbreviated SSL handshake may interact badly with Nagle */

        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

        if (clcf->tcp_nodelay && rap_tcp_nodelay(c) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    r->connection->log->action = "SSL handshaking to upstream";

    rc = rap_ssl_handshake(c);

    if (rc == RAP_AGAIN) {

        if (!c->write->timer_set) {
            rap_add_timer(c->write, u->conf->connect_timeout);
        }

        c->ssl->handler = rap_http_upstream_ssl_handshake_handler;
        return;
    }

    rap_http_upstream_ssl_handshake(r, u, c);
}


static void
rap_http_upstream_ssl_handshake_handler(rap_connection_t *c)
{
    rap_http_request_t   *r;
    rap_http_upstream_t  *u;

    r = c->data;

    u = r->upstream;
    c = r->connection;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream ssl handshake: \"%V?%V\"",
                   &r->uri, &r->args);

    rap_http_upstream_ssl_handshake(r, u, u->peer.connection);

    rap_http_run_posted_requests(c);
}


static void
rap_http_upstream_ssl_handshake(rap_http_request_t *r, rap_http_upstream_t *u,
    rap_connection_t *c)
{
    long  rc;

    if (c->ssl->handshaked) {

        if (u->conf->ssl_verify) {
            rc = SSL_get_verify_result(c->ssl->connection);

            if (rc != X509_V_OK) {
                rap_log_error(RAP_LOG_ERR, c->log, 0,
                              "upstream SSL certificate verify error: (%l:%s)",
                              rc, X509_verify_cert_error_string(rc));
                goto failed;
            }

            if (rap_ssl_check_host(c, &u->ssl_name) != RAP_OK) {
                rap_log_error(RAP_LOG_ERR, c->log, 0,
                              "upstream SSL certificate does not match \"%V\"",
                              &u->ssl_name);
                goto failed;
            }
        }

        c->write->handler = rap_http_upstream_handler;
        c->read->handler = rap_http_upstream_handler;

        rap_http_upstream_send_request(r, u, 1);

        return;
    }

    if (c->write->timedout) {
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

failed:

    rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_ERROR);
}


static void
rap_http_upstream_ssl_save_session(rap_connection_t *c)
{
    rap_http_request_t   *r;
    rap_http_upstream_t  *u;

    if (c->idle) {
        return;
    }

    r = c->data;

    u = r->upstream;
    c = r->connection;

    rap_http_set_log_request(c->log, r);

    u->peer.save_session(&u->peer, u->peer.data);
}


static rap_int_t
rap_http_upstream_ssl_name(rap_http_request_t *r, rap_http_upstream_t *u,
    rap_connection_t *c)
{
    u_char     *p, *last;
    rap_str_t   name;

    if (u->conf->ssl_name) {
        if (rap_http_complex_value(r, u->conf->ssl_name, &name) != RAP_OK) {
            return RAP_ERROR;
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
        p = rap_strlchr(p, last, ']');

        if (p == NULL) {
            p = name.data;
        }
    }

    p = rap_strlchr(p, last, ':');

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

    if (rap_inet_addr(name.data, name.len) != INADDR_NONE) {
        goto done;
    }

    /*
     * SSL_set_tlsext_host_name() needs a null-terminated string,
     * hence we explicitly null-terminate name here
     */

    p = rap_pnalloc(r->pool, name.len + 1);
    if (p == NULL) {
        return RAP_ERROR;
    }

    (void) rap_cpystrn(p, name.data, name.len + 1);

    name.data = p;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream SSL server name: \"%s\"", name.data);

    if (SSL_set_tlsext_host_name(c->ssl->connection,
                                 (char *) name.data)
        == 0)
    {
        rap_ssl_error(RAP_LOG_ERR, r->connection->log, 0,
                      "SSL_set_tlsext_host_name(\"%s\") failed", name.data);
        return RAP_ERROR;
    }

#endif

done:

    u->ssl_name = name;

    return RAP_OK;
}

#endif


static rap_int_t
rap_http_upstream_reinit(rap_http_request_t *r, rap_http_upstream_t *u)
{
    off_t         file_pos;
    rap_chain_t  *cl;

    if (u->reinit_request(r) != RAP_OK) {
        return RAP_ERROR;
    }

    u->keepalive = 0;
    u->upgrade = 0;

    rap_memzero(&u->headers_in, sizeof(rap_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;
    u->headers_in.last_modified_time = -1;

    if (rap_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(rap_table_elt_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (rap_list_init(&u->headers_in.trailers, r->pool, 2,
                      sizeof(rap_table_elt_t))
        != RAP_OK)
    {
        return RAP_ERROR;
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

    /* reinit the subrequest's rap_output_chain() context */

    if (r->request_body && r->request_body->temp_file
        && r != r->main && u->output.buf)
    {
        u->output.free = rap_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            return RAP_ERROR;
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

#if (RAP_HTTP_CACHE)

    if (r->cache) {
        u->buffer.pos += r->cache->header_start;
    }

#endif

    u->buffer.last = u->buffer.pos;

    return RAP_OK;
}


static void
rap_http_upstream_send_request(rap_http_request_t *r, rap_http_upstream_t *u,
    rap_uint_t do_write)
{
    rap_int_t          rc;
    rap_connection_t  *c;

    c = u->peer.connection;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream send request");

    if (u->state->connect_time == (rap_msec_t) -1) {
        u->state->connect_time = rap_current_msec - u->start_time;
    }

    if (!u->request_sent && rap_http_upstream_test_connect(c) != RAP_OK) {
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    c->log->action = "sending request to upstream";

    rc = rap_http_upstream_send_request_body(r, u, do_write);

    if (rc == RAP_ERROR) {
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (rc >= RAP_HTTP_SPECIAL_RESPONSE) {
        rap_http_upstream_finalize_request(r, u, rc);
        return;
    }

    if (rc == RAP_AGAIN) {
        if (!c->write->ready || u->request_body_blocked) {
            rap_add_timer(c->write, u->conf->send_timeout);

        } else if (c->write->timer_set) {
            rap_del_timer(c->write);
        }

        if (rap_handle_write_event(c->write, u->conf->send_lowat) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (c->write->ready && c->tcp_nopush == RAP_TCP_NOPUSH_SET) {
            if (rap_tcp_push(c->fd) == -1) {
                rap_log_error(RAP_LOG_CRIT, c->log, rap_socket_errno,
                              rap_tcp_push_n " failed");
                rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            c->tcp_nopush = RAP_TCP_NOPUSH_UNSET;
        }

        return;
    }

    /* rc == RAP_OK */

    if (c->write->timer_set) {
        rap_del_timer(c->write);
    }

    if (c->tcp_nopush == RAP_TCP_NOPUSH_SET) {
        if (rap_tcp_push(c->fd) == -1) {
            rap_log_error(RAP_LOG_CRIT, c->log, rap_socket_errno,
                          rap_tcp_push_n " failed");
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        c->tcp_nopush = RAP_TCP_NOPUSH_UNSET;
    }

    if (!u->conf->preserve_output) {
        u->write_event_handler = rap_http_upstream_dummy_handler;
    }

    if (rap_handle_write_event(c->write, 0) != RAP_OK) {
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (!u->request_body_sent) {
        u->request_body_sent = 1;

        if (u->header_sent) {
            return;
        }

        rap_add_timer(c->read, u->conf->read_timeout);

        if (c->read->ready) {
            rap_http_upstream_process_header(r, u);
            return;
        }
    }
}


static rap_int_t
rap_http_upstream_send_request_body(rap_http_request_t *r,
    rap_http_upstream_t *u, rap_uint_t do_write)
{
    rap_int_t                  rc;
    rap_chain_t               *out, *cl, *ln;
    rap_connection_t          *c;
    rap_http_core_loc_conf_t  *clcf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request body");

    if (!r->request_body_no_buffering) {

        /* buffered request body */

        if (!u->request_sent) {
            u->request_sent = 1;
            out = u->request_bufs;

        } else {
            out = NULL;
        }

        rc = rap_output_chain(&u->output, out);

        if (rc == RAP_AGAIN) {
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
        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

        if (clcf->tcp_nodelay && rap_tcp_nodelay(c) != RAP_OK) {
            return RAP_ERROR;
        }

        r->read_event_handler = rap_http_upstream_read_request_handler;

    } else {
        out = NULL;
    }

    for ( ;; ) {

        if (do_write) {
            rc = rap_output_chain(&u->output, out);

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            while (out) {
                ln = out;
                out = out->next;
                rap_free_chain(r->pool, ln);
            }

            if (rc == RAP_AGAIN) {
                u->request_body_blocked = 1;

            } else {
                u->request_body_blocked = 0;
            }

            if (rc == RAP_OK && !r->reading_body) {
                break;
            }
        }

        if (r->reading_body) {
            /* read client request body */

            rc = rap_http_read_unbuffered_request_body(r);

            if (rc >= RAP_HTTP_SPECIAL_RESPONSE) {
                return rc;
            }

            out = r->request_body->bufs;
            r->request_body->bufs = NULL;
        }

        /* stop if there is nothing to send */

        if (out == NULL) {
            rc = RAP_AGAIN;
            break;
        }

        do_write = 1;
    }

    if (!r->reading_body) {
        if (!u->store && !r->post_action && !u->conf->ignore_client_abort) {
            r->read_event_handler =
                                  rap_http_upstream_rd_check_broken_connection;
        }
    }

    return rc;
}


static void
rap_http_upstream_send_request_handler(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    rap_connection_t  *c;

    c = u->peer.connection;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream send request handler");

    if (c->write->timedout) {
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

#if (RAP_HTTP_SSL)

    if (u->ssl && c->ssl == NULL) {
        rap_http_upstream_ssl_init_connection(r, u, c);
        return;
    }

#endif

    if (u->header_sent && !u->conf->preserve_output) {
        u->write_event_handler = rap_http_upstream_dummy_handler;

        (void) rap_handle_write_event(c->write, 0);

        return;
    }

    rap_http_upstream_send_request(r, u, 1);
}


static void
rap_http_upstream_read_request_handler(rap_http_request_t *r)
{
    rap_connection_t     *c;
    rap_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream read request handler");

    if (c->read->timedout) {
        c->timedout = 1;
        rap_http_upstream_finalize_request(r, u, RAP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rap_http_upstream_send_request(r, u, 0);
}


static void
rap_http_upstream_process_header(rap_http_request_t *r, rap_http_upstream_t *u)
{
    ssize_t            n;
    rap_int_t          rc;
    rap_connection_t  *c;

    c = u->peer.connection;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process header");

    c->log->action = "reading response header from upstream";

    if (c->read->timedout) {
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }

    if (!u->request_sent && rap_http_upstream_test_connect(c) != RAP_OK) {
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_ERROR);
        return;
    }

    if (u->buffer.start == NULL) {
        u->buffer.start = rap_palloc(r->pool, u->conf->buffer_size);
        if (u->buffer.start == NULL) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
        u->buffer.end = u->buffer.start + u->conf->buffer_size;
        u->buffer.temporary = 1;

        u->buffer.tag = u->output.tag;

        if (rap_list_init(&u->headers_in.headers, r->pool, 8,
                          sizeof(rap_table_elt_t))
            != RAP_OK)
        {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (rap_list_init(&u->headers_in.trailers, r->pool, 2,
                          sizeof(rap_table_elt_t))
            != RAP_OK)
        {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

#if (RAP_HTTP_CACHE)

        if (r->cache) {
            u->buffer.pos += r->cache->header_start;
            u->buffer.last = u->buffer.pos;
        }
#endif
    }

    for ( ;; ) {

        n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);

        if (n == RAP_AGAIN) {
#if 0
            rap_add_timer(rev, u->read_timeout);
#endif

            if (rap_handle_read_event(c->read, 0) != RAP_OK) {
                rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            return;
        }

        if (n == 0) {
            rap_log_error(RAP_LOG_ERR, c->log, 0,
                          "upstream prematurely closed connection");
        }

        if (n == RAP_ERROR || n == 0) {
            rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_ERROR);
            return;
        }

        u->state->bytes_received += n;

        u->buffer.last += n;

#if 0
        u->valid_header_in = 0;

        u->peer.cached = 0;
#endif

        rc = u->process_header(r);

        if (rc == RAP_AGAIN) {

            if (u->buffer.last == u->buffer.end) {
                rap_log_error(RAP_LOG_ERR, c->log, 0,
                              "upstream sent too big header");

                rap_http_upstream_next(r, u,
                                       RAP_HTTP_UPSTREAM_FT_INVALID_HEADER);
                return;
            }

            continue;
        }

        break;
    }

    if (rc == RAP_HTTP_UPSTREAM_INVALID_HEADER) {
        rap_http_upstream_next(r, u, RAP_HTTP_UPSTREAM_FT_INVALID_HEADER);
        return;
    }

    if (rc == RAP_ERROR) {
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    /* rc == RAP_OK */

    u->state->header_time = rap_current_msec - u->start_time;

    if (u->headers_in.status_n >= RAP_HTTP_SPECIAL_RESPONSE) {

        if (rap_http_upstream_test_next(r, u) == RAP_OK) {
            return;
        }

        if (rap_http_upstream_intercept_errors(r, u) == RAP_OK) {
            return;
        }
    }

    if (rap_http_upstream_process_headers(r, u) != RAP_OK) {
        return;
    }

    rap_http_upstream_send_response(r, u);
}


static rap_int_t
rap_http_upstream_test_next(rap_http_request_t *r, rap_http_upstream_t *u)
{
    rap_msec_t                 timeout;
    rap_uint_t                 status, mask;
    rap_http_upstream_next_t  *un;

    status = u->headers_in.status_n;

    for (un = rap_http_upstream_next_errors; un->status; un++) {

        if (status != un->status) {
            continue;
        }

        timeout = u->conf->next_upstream_timeout;

        if (u->request_sent
            && (r->method & (RAP_HTTP_POST|RAP_HTTP_LOCK|RAP_HTTP_PATCH)))
        {
            mask = un->mask | RAP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;

        } else {
            mask = un->mask;
        }

        if (u->peer.tries > 1
            && ((u->conf->next_upstream & mask) == mask)
            && !(u->request_sent && r->request_body_no_buffering)
            && !(timeout && rap_current_msec - u->peer.start_time >= timeout))
        {
            rap_http_upstream_next(r, u, un->mask);
            return RAP_OK;
        }

#if (RAP_HTTP_CACHE)

        if (u->cache_status == RAP_HTTP_CACHE_EXPIRED
            && ((u->conf->cache_use_stale & un->mask) || r->cache->stale_error))
        {
            rap_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != RAP_OK) {
                rap_http_upstream_finalize_request(r, u, rc);
                return RAP_OK;
            }

            u->cache_status = RAP_HTTP_CACHE_STALE;
            rc = rap_http_upstream_cache_send(r, u);

            if (rc == RAP_DONE) {
                return RAP_OK;
            }

            if (rc == RAP_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = RAP_HTTP_INTERNAL_SERVER_ERROR;
            }

            rap_http_upstream_finalize_request(r, u, rc);
            return RAP_OK;
        }

#endif
    }

#if (RAP_HTTP_CACHE)

    if (status == RAP_HTTP_NOT_MODIFIED
        && u->cache_status == RAP_HTTP_CACHE_EXPIRED
        && u->conf->cache_revalidate)
    {
        time_t     now, valid, updating, error;
        rap_int_t  rc;

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream not modified");

        now = rap_time();

        valid = r->cache->valid_sec;
        updating = r->cache->updating_sec;
        error = r->cache->error_sec;

        rc = u->reinit_request(r);

        if (rc != RAP_OK) {
            rap_http_upstream_finalize_request(r, u, rc);
            return RAP_OK;
        }

        u->cache_status = RAP_HTTP_CACHE_REVALIDATED;
        rc = rap_http_upstream_cache_send(r, u);

        if (rc == RAP_DONE) {
            return RAP_OK;
        }

        if (rc == RAP_HTTP_UPSTREAM_INVALID_HEADER) {
            rc = RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (valid == 0) {
            valid = r->cache->valid_sec;
            updating = r->cache->updating_sec;
            error = r->cache->error_sec;
        }

        if (valid == 0) {
            valid = rap_http_file_cache_valid(u->conf->cache_valid,
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

            rap_http_file_cache_update_header(r);
        }

        rap_http_upstream_finalize_request(r, u, rc);
        return RAP_OK;
    }

#endif

    return RAP_DECLINED;
}


static rap_int_t
rap_http_upstream_intercept_errors(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    rap_int_t                  status;
    rap_uint_t                 i;
    rap_table_elt_t           *h;
    rap_http_err_page_t       *err_page;
    rap_http_core_loc_conf_t  *clcf;

    status = u->headers_in.status_n;

    if (status == RAP_HTTP_NOT_FOUND && u->conf->intercept_404) {
        rap_http_upstream_finalize_request(r, u, RAP_HTTP_NOT_FOUND);
        return RAP_OK;
    }

    if (!u->conf->intercept_errors) {
        return RAP_DECLINED;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (clcf->error_pages == NULL) {
        return RAP_DECLINED;
    }

    err_page = clcf->error_pages->elts;
    for (i = 0; i < clcf->error_pages->nelts; i++) {

        if (err_page[i].status == status) {

            if (status == RAP_HTTP_UNAUTHORIZED
                && u->headers_in.www_authenticate)
            {
                h = rap_list_push(&r->headers_out.headers);

                if (h == NULL) {
                    rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
                    return RAP_OK;
                }

                *h = *u->headers_in.www_authenticate;

                r->headers_out.www_authenticate = h;
            }

#if (RAP_HTTP_CACHE)

            if (r->cache) {

                if (u->cacheable) {
                    time_t  valid;

                    valid = r->cache->valid_sec;

                    if (valid == 0) {
                        valid = rap_http_file_cache_valid(u->conf->cache_valid,
                                                          status);
                        if (valid) {
                            r->cache->valid_sec = rap_time() + valid;
                        }
                    }

                    if (valid) {
                        r->cache->error = status;
                    }
                }

                rap_http_file_cache_free(r->cache, u->pipe->temp_file);
            }
#endif
            rap_http_upstream_finalize_request(r, u, status);

            return RAP_OK;
        }
    }

    return RAP_DECLINED;
}


static rap_int_t
rap_http_upstream_test_connect(rap_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (RAP_HAVE_KQUEUE)

    if (rap_event_flags & RAP_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) rap_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return RAP_ERROR;
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
            err = rap_socket_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) rap_connection_error(c, err, "connect() failed");
            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_headers(rap_http_request_t *r, rap_http_upstream_t *u)
{
    rap_str_t                       uri, args;
    rap_uint_t                      i, flags;
    rap_list_part_t                *part;
    rap_table_elt_t                *h;
    rap_http_upstream_header_t     *hh;
    rap_http_upstream_main_conf_t  *umcf;

    umcf = rap_http_get_module_main_conf(r, rap_http_upstream_module);

    if (u->headers_in.x_accel_redirect
        && !(u->conf->ignore_headers & RAP_HTTP_UPSTREAM_IGN_XA_REDIRECT))
    {
        rap_http_upstream_finalize_request(r, u, RAP_DECLINED);

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

            hh = rap_hash_find(&umcf->headers_in_hash, h[i].hash,
                               h[i].lowcase_key, h[i].key.len);

            if (hh && hh->redirect) {
                if (hh->copy_handler(r, &h[i], hh->conf) != RAP_OK) {
                    rap_http_finalize_request(r,
                                              RAP_HTTP_INTERNAL_SERVER_ERROR);
                    return RAP_DONE;
                }
            }
        }

        uri = u->headers_in.x_accel_redirect->value;

        if (uri.data[0] == '@') {
            rap_http_named_location(r, &uri);

        } else {
            rap_str_null(&args);
            flags = RAP_HTTP_LOG_UNSAFE;

            if (rap_http_parse_unsafe_uri(r, &uri, &args, &flags) != RAP_OK) {
                rap_http_finalize_request(r, RAP_HTTP_NOT_FOUND);
                return RAP_DONE;
            }

            if (r->method != RAP_HTTP_HEAD) {
                r->method = RAP_HTTP_GET;
                r->method_name = rap_http_core_get_method;
            }

            rap_http_internal_redirect(r, &uri, &args);
        }

        rap_http_finalize_request(r, RAP_DONE);
        return RAP_DONE;
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

        if (rap_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        hh = rap_hash_find(&umcf->headers_in_hash, h[i].hash,
                           h[i].lowcase_key, h[i].key.len);

        if (hh) {
            if (hh->copy_handler(r, &h[i], hh->conf) != RAP_OK) {
                rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
                return RAP_DONE;
            }

            continue;
        }

        if (rap_http_upstream_copy_header_line(r, &h[i], 0) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u,
                                               RAP_HTTP_INTERNAL_SERVER_ERROR);
            return RAP_DONE;
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

#if (RAP_HTTP_CACHE)
        if (r->cached) {
            r->single_range = 0;
        }
#endif
    }

    u->length = -1;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_trailers(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    rap_uint_t        i;
    rap_list_part_t  *part;
    rap_table_elt_t  *h, *ho;

    if (!u->conf->pass_trailers) {
        return RAP_OK;
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

        if (rap_hash_find(&u->conf->hide_headers_hash, h[i].hash,
                          h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }

        ho = rap_list_push(&r->headers_out.trailers);
        if (ho == NULL) {
            return RAP_ERROR;
        }

        *ho = h[i];
    }

    return RAP_OK;
}


static void
rap_http_upstream_send_response(rap_http_request_t *r, rap_http_upstream_t *u)
{
    ssize_t                    n;
    rap_int_t                  rc;
    rap_event_pipe_t          *p;
    rap_connection_t          *c;
    rap_http_core_loc_conf_t  *clcf;

    rc = rap_http_send_header(r);

    if (rc == RAP_ERROR || rc > RAP_OK || r->post_action) {
        rap_http_upstream_finalize_request(r, u, rc);
        return;
    }

    u->header_sent = 1;

    if (u->upgrade) {

#if (RAP_HTTP_CACHE)

        if (r->cache) {
            rap_http_file_cache_free(r->cache, u->pipe->temp_file);
        }

#endif

        rap_http_upstream_upgrade(r, u);
        return;
    }

    c = r->connection;

    if (r->header_only) {

        if (!u->buffering) {
            rap_http_upstream_finalize_request(r, u, rc);
            return;
        }

        if (!u->cacheable && !u->store) {
            rap_http_upstream_finalize_request(r, u, rc);
            return;
        }

        u->pipe->downstream_error = 1;
    }

    if (r->request_body && r->request_body->temp_file
        && r == r->main && !r->preserve_body
        && !u->conf->preserve_output)
    {
        rap_pool_run_cleanup_file(r->pool, r->request_body->temp_file->file.fd);
        r->request_body->temp_file->file.fd = RAP_INVALID_FILE;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (!u->buffering) {

#if (RAP_HTTP_CACHE)

        if (r->cache) {
            rap_http_file_cache_free(r->cache, u->pipe->temp_file);
        }

#endif

        if (u->input_filter == NULL) {
            u->input_filter_init = rap_http_upstream_non_buffered_filter_init;
            u->input_filter = rap_http_upstream_non_buffered_filter;
            u->input_filter_ctx = r;
        }

        u->read_event_handler = rap_http_upstream_process_non_buffered_upstream;
        r->write_event_handler =
                             rap_http_upstream_process_non_buffered_downstream;

        r->limit_rate = 0;
        r->limit_rate_set = 1;

        if (u->input_filter_init(u->input_filter_ctx) == RAP_ERROR) {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            return;
        }

        if (clcf->tcp_nodelay && rap_tcp_nodelay(c) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            return;
        }

        n = u->buffer.last - u->buffer.pos;

        if (n) {
            u->buffer.last = u->buffer.pos;

            u->state->response_length += n;

            if (u->input_filter(u->input_filter_ctx, n) == RAP_ERROR) {
                rap_http_upstream_finalize_request(r, u, RAP_ERROR);
                return;
            }

            rap_http_upstream_process_non_buffered_downstream(r);

        } else {
            u->buffer.pos = u->buffer.start;
            u->buffer.last = u->buffer.start;

            if (rap_http_send_special(r, RAP_HTTP_FLUSH) == RAP_ERROR) {
                rap_http_upstream_finalize_request(r, u, RAP_ERROR);
                return;
            }

            if (u->peer.connection->read->ready || u->length == 0) {
                rap_http_upstream_process_non_buffered_upstream(r, u);
            }
        }

        return;
    }

    /* TODO: preallocate event_pipe bufs, look "Content-Length" */

#if (RAP_HTTP_CACHE)

    if (r->cache && r->cache->file.fd != RAP_INVALID_FILE) {
        rap_pool_run_cleanup_file(r->pool, r->cache->file.fd);
        r->cache->file.fd = RAP_INVALID_FILE;
    }

    switch (rap_http_test_predicates(r, u->conf->no_cache)) {

    case RAP_ERROR:
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;

    case RAP_DECLINED:
        u->cacheable = 0;
        break;

    default: /* RAP_OK */

        if (u->cache_status == RAP_HTTP_CACHE_BYPASS) {

            /* create cache if previously bypassed */

            if (rap_http_file_cache_create(r) != RAP_OK) {
                rap_http_upstream_finalize_request(r, u, RAP_ERROR);
                return;
            }
        }

        break;
    }

    if (u->cacheable) {
        time_t  now, valid;

        now = rap_time();

        valid = r->cache->valid_sec;

        if (valid == 0) {
            valid = rap_http_file_cache_valid(u->conf->cache_valid,
                                              u->headers_in.status_n);
            if (valid) {
                r->cache->valid_sec = now + valid;
            }
        }

        if (valid) {
            r->cache->date = now;
            r->cache->body_start = (u_short) (u->buffer.pos - u->buffer.start);

            if (u->headers_in.status_n == RAP_HTTP_OK
                || u->headers_in.status_n == RAP_HTTP_PARTIAL_CONTENT)
            {
                r->cache->last_modified = u->headers_in.last_modified_time;

                if (u->headers_in.etag) {
                    r->cache->etag = u->headers_in.etag->value;

                } else {
                    rap_str_null(&r->cache->etag);
                }

            } else {
                r->cache->last_modified = -1;
                rap_str_null(&r->cache->etag);
            }

            if (rap_http_file_cache_set_header(r, u->buffer.start) != RAP_OK) {
                rap_http_upstream_finalize_request(r, u, RAP_ERROR);
                return;
            }

        } else {
            u->cacheable = 0;
        }
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http cacheable: %d", u->cacheable);

    if (u->cacheable == 0 && r->cache) {
        rap_http_file_cache_free(r->cache, u->pipe->temp_file);
    }

    if (r->header_only && !u->cacheable && !u->store) {
        rap_http_upstream_finalize_request(r, u, 0);
        return;
    }

#endif

    p = u->pipe;

    p->output_filter = rap_http_upstream_output_filter;
    p->output_ctx = r;
    p->tag = u->output.tag;
    p->bufs = u->conf->bufs;
    p->busy_size = u->conf->busy_buffers_size;
    p->upstream = u->peer.connection;
    p->downstream = c;
    p->pool = r->pool;
    p->log = c->log;
    p->limit_rate = u->conf->limit_rate;
    p->start_sec = rap_time();

    p->cacheable = u->cacheable || u->store;

    p->temp_file = rap_pcalloc(r->pool, sizeof(rap_temp_file_t));
    if (p->temp_file == NULL) {
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    p->temp_file->file.fd = RAP_INVALID_FILE;
    p->temp_file->file.log = c->log;
    p->temp_file->path = u->conf->temp_path;
    p->temp_file->pool = r->pool;

    if (p->cacheable) {
        p->temp_file->persistent = 1;

#if (RAP_HTTP_CACHE)
        if (r->cache && !r->cache->file_cache->use_temp_path) {
            p->temp_file->path = r->cache->file_cache->path;
            p->temp_file->file.name = r->cache->file.name;
        }
#endif

    } else {
        p->temp_file->log_level = RAP_LOG_WARN;
        p->temp_file->warn = "an upstream response is buffered "
                             "to a temporary file";
    }

    p->max_temp_file_size = u->conf->max_temp_file_size;
    p->temp_file_write_size = u->conf->temp_file_write_size;

#if (RAP_THREADS)
    if (clcf->aio == RAP_HTTP_AIO_THREADS && clcf->aio_write) {
        p->thread_handler = rap_http_upstream_thread_handler;
        p->thread_ctx = r;
    }
#endif

    p->preread_bufs = rap_alloc_chain_link(r->pool);
    if (p->preread_bufs == NULL) {
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    p->preread_bufs->buf = &u->buffer;
    p->preread_bufs->next = NULL;
    u->buffer.recycled = 1;

    p->preread_size = u->buffer.last - u->buffer.pos;

    if (u->cacheable) {

        p->buf_to_file = rap_calloc_buf(r->pool);
        if (p->buf_to_file == NULL) {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            return;
        }

        p->buf_to_file->start = u->buffer.start;
        p->buf_to_file->pos = u->buffer.start;
        p->buf_to_file->last = u->buffer.pos;
        p->buf_to_file->temporary = 1;
    }

    if (rap_event_flags & RAP_USE_IOCP_EVENT) {
        /* the posted aio operation may corrupt a shadow buffer */
        p->single_buf = 1;
    }

    /* TODO: p->free_bufs = 0 if use rap_create_chain_of_bufs() */
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
        && u->input_filter_init(p->input_ctx) != RAP_OK)
    {
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    u->read_event_handler = rap_http_upstream_process_upstream;
    r->write_event_handler = rap_http_upstream_process_downstream;

    rap_http_upstream_process_upstream(r, u);
}


static void
rap_http_upstream_upgrade(rap_http_request_t *r, rap_http_upstream_t *u)
{
    rap_connection_t          *c;
    rap_http_core_loc_conf_t  *clcf;

    c = r->connection;
    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    /* TODO: prevent upgrade if not requested or not possible */

    if (r != r->main) {
        rap_log_error(RAP_LOG_ERR, c->log, 0,
                      "connection upgrade in subrequest");
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    r->keepalive = 0;
    c->log->action = "proxying upgraded connection";

    u->read_event_handler = rap_http_upstream_upgraded_read_upstream;
    u->write_event_handler = rap_http_upstream_upgraded_write_upstream;
    r->read_event_handler = rap_http_upstream_upgraded_read_downstream;
    r->write_event_handler = rap_http_upstream_upgraded_write_downstream;

    if (clcf->tcp_nodelay) {

        if (rap_tcp_nodelay(c) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            return;
        }

        if (rap_tcp_nodelay(u->peer.connection) != RAP_OK) {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            return;
        }
    }

    if (rap_http_send_special(r, RAP_HTTP_FLUSH) == RAP_ERROR) {
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    if (u->peer.connection->read->ready
        || u->buffer.pos != u->buffer.last)
    {
        rap_post_event(c->read, &rap_posted_events);
        rap_http_upstream_process_upgraded(r, 1, 1);
        return;
    }

    rap_http_upstream_process_upgraded(r, 0, 1);
}


static void
rap_http_upstream_upgraded_read_downstream(rap_http_request_t *r)
{
    rap_http_upstream_process_upgraded(r, 0, 0);
}


static void
rap_http_upstream_upgraded_write_downstream(rap_http_request_t *r)
{
    rap_http_upstream_process_upgraded(r, 1, 1);
}


static void
rap_http_upstream_upgraded_read_upstream(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    rap_http_upstream_process_upgraded(r, 1, 0);
}


static void
rap_http_upstream_upgraded_write_upstream(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    rap_http_upstream_process_upgraded(r, 0, 1);
}


static void
rap_http_upstream_process_upgraded(rap_http_request_t *r,
    rap_uint_t from_upstream, rap_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    rap_buf_t                 *b;
    rap_uint_t                 flags;
    rap_connection_t          *c, *downstream, *upstream, *dst, *src;
    rap_http_upstream_t       *u;
    rap_http_core_loc_conf_t  *clcf;

    c = r->connection;
    u = r->upstream;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upgraded, fu:%ui", from_upstream);

    downstream = c;
    upstream = u->peer.connection;

    if (downstream->write->timedout) {
        c->timedout = 1;
        rap_connection_error(c, RAP_ETIMEDOUT, "client timed out");
        rap_http_upstream_finalize_request(r, u, RAP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (upstream->read->timedout || upstream->write->timedout) {
        rap_connection_error(c, RAP_ETIMEDOUT, "upstream timed out");
        rap_http_upstream_finalize_request(r, u, RAP_HTTP_GATEWAY_TIME_OUT);
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
            b->start = rap_palloc(r->pool, u->conf->buffer_size);
            if (b->start == NULL) {
                rap_http_upstream_finalize_request(r, u, RAP_ERROR);
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

                if (n == RAP_ERROR) {
                    rap_http_upstream_finalize_request(r, u, RAP_ERROR);
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

            if (n == RAP_AGAIN || n == 0) {
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

            if (n == RAP_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    if ((upstream->read->eof && u->buffer.pos == u->buffer.last)
        || (downstream->read->eof && u->from_client.pos == u->from_client.last)
        || (downstream->read->eof && upstream->read->eof))
    {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream upgraded done");
        rap_http_upstream_finalize_request(r, u, 0);
        return;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (rap_handle_write_event(upstream->write, u->conf->send_lowat)
        != RAP_OK)
    {
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    if (upstream->write->active && !upstream->write->ready) {
        rap_add_timer(upstream->write, u->conf->send_timeout);

    } else if (upstream->write->timer_set) {
        rap_del_timer(upstream->write);
    }

    if (upstream->read->eof || upstream->read->error) {
        flags = RAP_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (rap_handle_read_event(upstream->read, flags) != RAP_OK) {
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        rap_add_timer(upstream->read, u->conf->read_timeout);

    } else if (upstream->read->timer_set) {
        rap_del_timer(upstream->read);
    }

    if (rap_handle_write_event(downstream->write, clcf->send_lowat)
        != RAP_OK)
    {
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    if (downstream->read->eof || downstream->read->error) {
        flags = RAP_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (rap_handle_read_event(downstream->read, flags) != RAP_OK) {
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    if (downstream->write->active && !downstream->write->ready) {
        rap_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        rap_del_timer(downstream->write);
    }
}


static void
rap_http_upstream_process_non_buffered_downstream(rap_http_request_t *r)
{
    rap_event_t          *wev;
    rap_connection_t     *c;
    rap_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    wev = c->write;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered downstream");

    c->log->action = "sending to client";

    if (wev->timedout) {
        c->timedout = 1;
        rap_connection_error(c, RAP_ETIMEDOUT, "client timed out");
        rap_http_upstream_finalize_request(r, u, RAP_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rap_http_upstream_process_non_buffered_request(r, 1);
}


static void
rap_http_upstream_process_non_buffered_upstream(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    rap_connection_t  *c;

    c = u->peer.connection;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered upstream");

    c->log->action = "reading upstream";

    if (c->read->timedout) {
        rap_connection_error(c, RAP_ETIMEDOUT, "upstream timed out");
        rap_http_upstream_finalize_request(r, u, RAP_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    rap_http_upstream_process_non_buffered_request(r, 0);
}


static void
rap_http_upstream_process_non_buffered_request(rap_http_request_t *r,
    rap_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    rap_buf_t                 *b;
    rap_int_t                  rc;
    rap_uint_t                 flags;
    rap_connection_t          *downstream, *upstream;
    rap_http_upstream_t       *u;
    rap_http_core_loc_conf_t  *clcf;

    u = r->upstream;
    downstream = r->connection;
    upstream = u->peer.connection;

    b = &u->buffer;

    do_write = do_write || u->length == 0;

    for ( ;; ) {

        if (do_write) {

            if (u->out_bufs || u->busy_bufs || downstream->buffered) {
                rc = rap_http_output_filter(r, u->out_bufs);

                if (rc == RAP_ERROR) {
                    rap_http_upstream_finalize_request(r, u, RAP_ERROR);
                    return;
                }

                rap_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,
                                        &u->out_bufs, u->output.tag);
            }

            if (u->busy_bufs == NULL) {

                if (u->length == 0
                    || (upstream->read->eof && u->length == -1))
                {
                    rap_http_upstream_finalize_request(r, u, 0);
                    return;
                }

                if (upstream->read->eof) {
                    rap_log_error(RAP_LOG_ERR, upstream->log, 0,
                                  "upstream prematurely closed connection");

                    rap_http_upstream_finalize_request(r, u,
                                                       RAP_HTTP_BAD_GATEWAY);
                    return;
                }

                if (upstream->read->error) {
                    rap_http_upstream_finalize_request(r, u,
                                                       RAP_HTTP_BAD_GATEWAY);
                    return;
                }

                b->pos = b->start;
                b->last = b->start;
            }
        }

        size = b->end - b->last;

        if (size && upstream->read->ready) {

            n = upstream->recv(upstream, b->last, size);

            if (n == RAP_AGAIN) {
                break;
            }

            if (n > 0) {
                u->state->bytes_received += n;
                u->state->response_length += n;

                if (u->input_filter(u->input_filter_ctx, n) == RAP_ERROR) {
                    rap_http_upstream_finalize_request(r, u, RAP_ERROR);
                    return;
                }
            }

            do_write = 1;

            continue;
        }

        break;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (downstream->data == r) {
        if (rap_handle_write_event(downstream->write, clcf->send_lowat)
            != RAP_OK)
        {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            return;
        }
    }

    if (downstream->write->active && !downstream->write->ready) {
        rap_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        rap_del_timer(downstream->write);
    }

    if (upstream->read->eof || upstream->read->error) {
        flags = RAP_CLOSE_EVENT;

    } else {
        flags = 0;
    }

    if (rap_handle_read_event(upstream->read, flags) != RAP_OK) {
        rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        rap_add_timer(upstream->read, u->conf->read_timeout);

    } else if (upstream->read->timer_set) {
        rap_del_timer(upstream->read);
    }
}


static rap_int_t
rap_http_upstream_non_buffered_filter_init(void *data)
{
    return RAP_OK;
}


static rap_int_t
rap_http_upstream_non_buffered_filter(void *data, ssize_t bytes)
{
    rap_http_request_t  *r = data;

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

    return RAP_OK;
}


#if (RAP_THREADS)

static rap_int_t
rap_http_upstream_thread_handler(rap_thread_task_t *task, rap_file_t *file)
{
    rap_str_t                  name;
    rap_event_pipe_t          *p;
    rap_thread_pool_t         *tp;
    rap_http_request_t        *r;
    rap_http_core_loc_conf_t  *clcf;

    r = file->thread_ctx;
    p = r->upstream->pipe;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);
    tp = clcf->thread_pool;

    if (tp == NULL) {
        if (rap_http_complex_value(r, clcf->thread_pool_value, &name)
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        tp = rap_thread_pool_get((rap_cycle_t *) rap_cycle, &name);

        if (tp == NULL) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "thread pool \"%V\" not found", &name);
            return RAP_ERROR;
        }
    }

    task->event.data = r;
    task->event.handler = rap_http_upstream_thread_event_handler;

    if (rap_thread_task_post(tp, task) != RAP_OK) {
        return RAP_ERROR;
    }

    r->main->blocked++;
    r->aio = 1;
    p->aio = 1;

    return RAP_OK;
}


static void
rap_http_upstream_thread_event_handler(rap_event_t *ev)
{
    rap_connection_t    *c;
    rap_http_request_t  *r;

    r = ev->data;
    c = r->connection;

    rap_http_set_log_request(c->log, r);

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
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
        rap_http_run_posted_requests(c);
    }
}

#endif


static rap_int_t
rap_http_upstream_output_filter(void *data, rap_chain_t *chain)
{
    rap_int_t            rc;
    rap_event_pipe_t    *p;
    rap_http_request_t  *r;

    r = data;
    p = r->upstream->pipe;

    rc = rap_http_output_filter(r, chain);

    p->aio = r->aio;

    return rc;
}


static void
rap_http_upstream_process_downstream(rap_http_request_t *r)
{
    rap_event_t          *wev;
    rap_connection_t     *c;
    rap_event_pipe_t     *p;
    rap_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    p = u->pipe;
    wev = c->write;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process downstream");

    c->log->action = "sending to client";

#if (RAP_THREADS)
    p->aio = r->aio;
#endif

    if (wev->timedout) {

        p->downstream_error = 1;
        c->timedout = 1;
        rap_connection_error(c, RAP_ETIMEDOUT, "client timed out");

    } else {

        if (wev->delayed) {

            rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                           "http downstream delayed");

            if (rap_handle_write_event(wev, p->send_lowat) != RAP_OK) {
                rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            }

            return;
        }

        if (rap_event_pipe(p, 1) == RAP_ABORT) {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            return;
        }
    }

    rap_http_upstream_process_request(r, u);
}


static void
rap_http_upstream_process_upstream(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    rap_event_t       *rev;
    rap_event_pipe_t  *p;
    rap_connection_t  *c;

    c = u->peer.connection;
    p = u->pipe;
    rev = c->read;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upstream");

    c->log->action = "reading upstream";

    if (rev->timedout) {

        p->upstream_error = 1;
        rap_connection_error(c, RAP_ETIMEDOUT, "upstream timed out");

    } else {

        if (rev->delayed) {

            rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                           "http upstream delayed");

            if (rap_handle_read_event(rev, 0) != RAP_OK) {
                rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            }

            return;
        }

        if (rap_event_pipe(p, 0) == RAP_ABORT) {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
            return;
        }
    }

    rap_http_upstream_process_request(r, u);
}


static void
rap_http_upstream_process_request(rap_http_request_t *r,
    rap_http_upstream_t *u)
{
    rap_temp_file_t   *tf;
    rap_event_pipe_t  *p;

    p = u->pipe;

#if (RAP_THREADS)

    if (p->writing && !p->aio) {

        /*
         * make sure to call rap_event_pipe()
         * if there is an incomplete aio write
         */

        if (rap_event_pipe(p, 1) == RAP_ABORT) {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
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

                if (u->headers_in.status_n == RAP_HTTP_OK
                    && (p->upstream_done || p->length == -1)
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n == tf->offset))
                {
                    rap_http_upstream_store(r, u);
                }
            }
        }

#if (RAP_HTTP_CACHE)

        if (u->cacheable) {

            if (p->upstream_done) {
                rap_http_file_cache_update(r, p->temp_file);

            } else if (p->upstream_eof) {

                tf = p->temp_file;

                if (p->length == -1
                    && (u->headers_in.content_length_n == -1
                        || u->headers_in.content_length_n
                           == tf->offset - (off_t) r->cache->body_start))
                {
                    rap_http_file_cache_update(r, tf);

                } else {
                    rap_http_file_cache_free(r->cache, tf);
                }

            } else if (p->upstream_error) {
                rap_http_file_cache_free(r->cache, p->temp_file);
            }
        }

#endif

        if (p->upstream_done || p->upstream_eof || p->upstream_error) {
            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http upstream exit: %p", p->out);

            if (p->upstream_done
                || (p->upstream_eof && p->length == -1))
            {
                rap_http_upstream_finalize_request(r, u, 0);
                return;
            }

            if (p->upstream_eof) {
                rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                              "upstream prematurely closed connection");
            }

            rap_http_upstream_finalize_request(r, u, RAP_HTTP_BAD_GATEWAY);
            return;
        }
    }

    if (p->downstream_error) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream downstream error");

        if (!u->cacheable && !u->store && u->peer.connection) {
            rap_http_upstream_finalize_request(r, u, RAP_ERROR);
        }
    }
}


static void
rap_http_upstream_store(rap_http_request_t *r, rap_http_upstream_t *u)
{
    size_t                  root;
    time_t                  lm;
    rap_str_t               path;
    rap_temp_file_t        *tf;
    rap_ext_rename_file_t   ext;

    tf = u->pipe->temp_file;

    if (tf->file.fd == RAP_INVALID_FILE) {

        /* create file for empty 200 response */

        tf = rap_pcalloc(r->pool, sizeof(rap_temp_file_t));
        if (tf == NULL) {
            return;
        }

        tf->file.fd = RAP_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = u->conf->temp_path;
        tf->pool = r->pool;
        tf->persistent = 1;

        if (rap_create_temp_file(&tf->file, tf->path, tf->pool,
                                 tf->persistent, tf->clean, tf->access)
            != RAP_OK)
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

        lm = rap_parse_http_time(u->headers_in.last_modified->value.data,
                                 u->headers_in.last_modified->value.len);

        if (lm != RAP_ERROR) {
            ext.time = lm;
            ext.fd = tf->file.fd;
        }
    }

    if (u->conf->store_lengths == NULL) {

        if (rap_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
            return;
        }

    } else {
        if (rap_http_script_run(r, &path, u->conf->store_lengths->elts, 0,
                                u->conf->store_values->elts)
            == NULL)
        {
            return;
        }
    }

    path.len--;

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream stores \"%s\" to \"%s\"",
                   tf->file.name.data, path.data);

    (void) rap_ext_rename_file(&tf->file.name, &path, &ext);

    u->store = 0;
}


static void
rap_http_upstream_dummy_handler(rap_http_request_t *r, rap_http_upstream_t *u)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream dummy handler");
}


static void
rap_http_upstream_next(rap_http_request_t *r, rap_http_upstream_t *u,
    rap_uint_t ft_type)
{
    rap_msec_t  timeout;
    rap_uint_t  status, state;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http next upstream, %xi", ft_type);

    if (u->peer.sockaddr) {

        if (u->peer.connection) {
            u->state->bytes_sent = u->peer.connection->sent;
        }

        if (ft_type == RAP_HTTP_UPSTREAM_FT_HTTP_403
            || ft_type == RAP_HTTP_UPSTREAM_FT_HTTP_404)
        {
            state = RAP_PEER_NEXT;

        } else {
            state = RAP_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (ft_type == RAP_HTTP_UPSTREAM_FT_TIMEOUT) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, RAP_ETIMEDOUT,
                      "upstream timed out");
    }

    if (u->peer.cached && ft_type == RAP_HTTP_UPSTREAM_FT_ERROR) {
        /* TODO: inform balancer instead */
        u->peer.tries++;
    }

    switch (ft_type) {

    case RAP_HTTP_UPSTREAM_FT_TIMEOUT:
    case RAP_HTTP_UPSTREAM_FT_HTTP_504:
        status = RAP_HTTP_GATEWAY_TIME_OUT;
        break;

    case RAP_HTTP_UPSTREAM_FT_HTTP_500:
        status = RAP_HTTP_INTERNAL_SERVER_ERROR;
        break;

    case RAP_HTTP_UPSTREAM_FT_HTTP_503:
        status = RAP_HTTP_SERVICE_UNAVAILABLE;
        break;

    case RAP_HTTP_UPSTREAM_FT_HTTP_403:
        status = RAP_HTTP_FORBIDDEN;
        break;

    case RAP_HTTP_UPSTREAM_FT_HTTP_404:
        status = RAP_HTTP_NOT_FOUND;
        break;

    case RAP_HTTP_UPSTREAM_FT_HTTP_429:
        status = RAP_HTTP_TOO_MANY_REQUESTS;
        break;

    /*
     * RAP_HTTP_UPSTREAM_FT_BUSY_LOCK and RAP_HTTP_UPSTREAM_FT_MAX_WAITING
     * never reach here
     */

    default:
        status = RAP_HTTP_BAD_GATEWAY;
    }

    if (r->connection->error) {
        rap_http_upstream_finalize_request(r, u,
                                           RAP_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    u->state->status = status;

    timeout = u->conf->next_upstream_timeout;

    if (u->request_sent
        && (r->method & (RAP_HTTP_POST|RAP_HTTP_LOCK|RAP_HTTP_PATCH)))
    {
        ft_type |= RAP_HTTP_UPSTREAM_FT_NON_IDEMPOTENT;
    }

    if (u->peer.tries == 0
        || ((u->conf->next_upstream & ft_type) != ft_type)
        || (u->request_sent && r->request_body_no_buffering)
        || (timeout && rap_current_msec - u->peer.start_time >= timeout))
    {
#if (RAP_HTTP_CACHE)

        if (u->cache_status == RAP_HTTP_CACHE_EXPIRED
            && ((u->conf->cache_use_stale & ft_type) || r->cache->stale_error))
        {
            rap_int_t  rc;

            rc = u->reinit_request(r);

            if (rc != RAP_OK) {
                rap_http_upstream_finalize_request(r, u, rc);
                return;
            }

            u->cache_status = RAP_HTTP_CACHE_STALE;
            rc = rap_http_upstream_cache_send(r, u);

            if (rc == RAP_DONE) {
                return;
            }

            if (rc == RAP_HTTP_UPSTREAM_INVALID_HEADER) {
                rc = RAP_HTTP_INTERNAL_SERVER_ERROR;
            }

            rap_http_upstream_finalize_request(r, u, rc);
            return;
        }
#endif

        rap_http_upstream_finalize_request(r, u, status);
        return;
    }

    if (u->peer.connection) {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);
#if (RAP_HTTP_SSL)

        if (u->peer.connection->ssl) {
            u->peer.connection->ssl->no_wait_shutdown = 1;
            u->peer.connection->ssl->no_send_shutdown = 1;

            (void) rap_ssl_shutdown(u->peer.connection);
        }
#endif

        if (u->peer.connection->pool) {
            rap_destroy_pool(u->peer.connection->pool);
        }

        rap_close_connection(u->peer.connection);
        u->peer.connection = NULL;
    }

    rap_http_upstream_connect(r, u);
}


static void
rap_http_upstream_cleanup(void *data)
{
    rap_http_request_t *r = data;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cleanup http upstream request: \"%V\"", &r->uri);

    rap_http_upstream_finalize_request(r, r->upstream, RAP_DONE);
}


static void
rap_http_upstream_finalize_request(rap_http_request_t *r,
    rap_http_upstream_t *u, rap_int_t rc)
{
    rap_uint_t  flush;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http upstream request: %i", rc);

    if (u->cleanup == NULL) {
        /* the request was already finalized */
        rap_http_finalize_request(r, RAP_DONE);
        return;
    }

    *u->cleanup = NULL;
    u->cleanup = NULL;

    if (u->resolved && u->resolved->ctx) {
        rap_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

    if (u->state && u->state->response_time == (rap_msec_t) -1) {
        u->state->response_time = rap_current_msec - u->start_time;

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

#if (RAP_HTTP_SSL)

        /* TODO: do not shutdown persistent connection */

        if (u->peer.connection->ssl) {

            /*
             * We send the "close notify" shutdown alert to the upstream only
             * and do not wait its "close notify" shutdown alert.
             * It is acceptable according to the TLS standard.
             */

            u->peer.connection->ssl->no_wait_shutdown = 1;

            (void) rap_ssl_shutdown(u->peer.connection);
        }
#endif

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            rap_destroy_pool(u->peer.connection->pool);
        }

        rap_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->pipe && u->pipe->temp_file) {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream temp fd: %d",
                       u->pipe->temp_file->file.fd);
    }

    if (u->store && u->pipe && u->pipe->temp_file
        && u->pipe->temp_file->file.fd != RAP_INVALID_FILE)
    {
        if (rap_delete_file(u->pipe->temp_file->file.name.data)
            == RAP_FILE_ERROR)
        {
            rap_log_error(RAP_LOG_CRIT, r->connection->log, rap_errno,
                          rap_delete_file_n " \"%s\" failed",
                          u->pipe->temp_file->file.name.data);
        }
    }

#if (RAP_HTTP_CACHE)

    if (r->cache) {

        if (u->cacheable) {

            if (rc == RAP_HTTP_BAD_GATEWAY || rc == RAP_HTTP_GATEWAY_TIME_OUT) {
                time_t  valid;

                valid = rap_http_file_cache_valid(u->conf->cache_valid, rc);

                if (valid) {
                    r->cache->valid_sec = rap_time() + valid;
                    r->cache->error = rc;
                }
            }
        }

        rap_http_file_cache_free(r->cache, u->pipe->temp_file);
    }

#endif

    r->read_event_handler = rap_http_block_reading;

    if (rc == RAP_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (!u->header_sent
        || rc == RAP_HTTP_REQUEST_TIME_OUT
        || rc == RAP_HTTP_CLIENT_CLOSED_REQUEST)
    {
        rap_http_finalize_request(r, rc);
        return;
    }

    flush = 0;

    if (rc >= RAP_HTTP_SPECIAL_RESPONSE) {
        rc = RAP_ERROR;
        flush = 1;
    }

    if (r->header_only
        || (u->pipe && u->pipe->downstream_error))
    {
        rap_http_finalize_request(r, rc);
        return;
    }

    if (rc == 0) {

        if (rap_http_upstream_process_trailers(r, u) != RAP_OK) {
            rap_http_finalize_request(r, RAP_ERROR);
            return;
        }

        rc = rap_http_send_special(r, RAP_HTTP_LAST);

    } else if (flush) {
        r->keepalive = 0;
        rc = rap_http_send_special(r, RAP_HTTP_FLUSH);
    }

    rap_http_finalize_request(r, rc);
}


static rap_int_t
rap_http_upstream_process_header_line(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_table_elt_t  **ph;

    ph = (rap_table_elt_t **) ((char *) &r->upstream->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_ignore_header_line(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_content_length(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset)
{
    rap_http_upstream_t  *u;

    u = r->upstream;

    u->headers_in.content_length = h;
    u->headers_in.content_length_n = rap_atoof(h->value.data, h->value.len);

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_last_modified(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset)
{
    rap_http_upstream_t  *u;

    u = r->upstream;

    u->headers_in.last_modified = h;
    u->headers_in.last_modified_time = rap_parse_http_time(h->value.data,
                                                           h->value.len);

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_set_cookie(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_array_t           *pa;
    rap_table_elt_t      **ph;
    rap_http_upstream_t   *u;

    u = r->upstream;
    pa = &u->headers_in.cookies;

    if (pa->elts == NULL) {
        if (rap_array_init(pa, r->pool, 1, sizeof(rap_table_elt_t *)) != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    ph = rap_array_push(pa);
    if (ph == NULL) {
        return RAP_ERROR;
    }

    *ph = h;

#if (RAP_HTTP_CACHE)
    if (!(u->conf->ignore_headers & RAP_HTTP_UPSTREAM_IGN_SET_COOKIE)) {
        u->cacheable = 0;
    }
#endif

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_cache_control(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset)
{
    rap_array_t          *pa;
    rap_table_elt_t     **ph;
    rap_http_upstream_t  *u;

    u = r->upstream;
    pa = &u->headers_in.cache_control;

    if (pa->elts == NULL) {
        if (rap_array_init(pa, r->pool, 2, sizeof(rap_table_elt_t *)) != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    ph = rap_array_push(pa);
    if (ph == NULL) {
        return RAP_ERROR;
    }

    *ph = h;

#if (RAP_HTTP_CACHE)
    {
    u_char     *p, *start, *last;
    rap_int_t   n;

    if (u->conf->ignore_headers & RAP_HTTP_UPSTREAM_IGN_CACHE_CONTROL) {
        return RAP_OK;
    }

    if (r->cache == NULL) {
        return RAP_OK;
    }

    if (r->cache->valid_sec != 0 && u->headers_in.x_accel_expires != NULL) {
        return RAP_OK;
    }

    start = h->value.data;
    last = start + h->value.len;

    if (rap_strlcasestrn(start, last, (u_char *) "no-cache", 8 - 1) != NULL
        || rap_strlcasestrn(start, last, (u_char *) "no-store", 8 - 1) != NULL
        || rap_strlcasestrn(start, last, (u_char *) "private", 7 - 1) != NULL)
    {
        u->cacheable = 0;
        return RAP_OK;
    }

    p = rap_strlcasestrn(start, last, (u_char *) "s-maxage=", 9 - 1);
    offset = 9;

    if (p == NULL) {
        p = rap_strlcasestrn(start, last, (u_char *) "max-age=", 8 - 1);
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
            return RAP_OK;
        }

        if (n == 0) {
            u->cacheable = 0;
            return RAP_OK;
        }

        r->cache->valid_sec = rap_time() + n;
    }

    p = rap_strlcasestrn(start, last, (u_char *) "stale-while-revalidate=",
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
            return RAP_OK;
        }

        r->cache->updating_sec = n;
        r->cache->error_sec = n;
    }

    p = rap_strlcasestrn(start, last, (u_char *) "stale-if-error=", 15 - 1);

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
            return RAP_OK;
        }

        r->cache->error_sec = n;
    }
    }
#endif

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_expires(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.expires = h;

#if (RAP_HTTP_CACHE)
    {
    time_t  expires;

    if (u->conf->ignore_headers & RAP_HTTP_UPSTREAM_IGN_EXPIRES) {
        return RAP_OK;
    }

    if (r->cache == NULL) {
        return RAP_OK;
    }

    if (r->cache->valid_sec != 0) {
        return RAP_OK;
    }

    expires = rap_parse_http_time(h->value.data, h->value.len);

    if (expires == RAP_ERROR || expires < rap_time()) {
        u->cacheable = 0;
        return RAP_OK;
    }

    r->cache->valid_sec = expires;
    }
#endif

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_accel_expires(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset)
{
    rap_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.x_accel_expires = h;

#if (RAP_HTTP_CACHE)
    {
    u_char     *p;
    size_t      len;
    rap_int_t   n;

    if (u->conf->ignore_headers & RAP_HTTP_UPSTREAM_IGN_XA_EXPIRES) {
        return RAP_OK;
    }

    if (r->cache == NULL) {
        return RAP_OK;
    }

    len = h->value.len;
    p = h->value.data;

    if (p[0] != '@') {
        n = rap_atoi(p, len);

        switch (n) {
        case 0:
            u->cacheable = 0;
            /* fall through */

        case RAP_ERROR:
            return RAP_OK;

        default:
            r->cache->valid_sec = rap_time() + n;
            return RAP_OK;
        }
    }

    p++;
    len--;

    n = rap_atoi(p, len);

    if (n != RAP_ERROR) {
        r->cache->valid_sec = n;
    }
    }
#endif

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_limit_rate(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_int_t             n;
    rap_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.x_accel_limit_rate = h;

    if (u->conf->ignore_headers & RAP_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE) {
        return RAP_OK;
    }

    n = rap_atoi(h->value.data, h->value.len);

    if (n != RAP_ERROR) {
        r->limit_rate = (size_t) n;
        r->limit_rate_set = 1;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_buffering(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    u_char                c0, c1, c2;
    rap_http_upstream_t  *u;

    u = r->upstream;

    if (u->conf->ignore_headers & RAP_HTTP_UPSTREAM_IGN_XA_BUFFERING) {
        return RAP_OK;
    }

    if (u->conf->change_buffering) {

        if (h->value.len == 2) {
            c0 = rap_tolower(h->value.data[0]);
            c1 = rap_tolower(h->value.data[1]);

            if (c0 == 'n' && c1 == 'o') {
                u->buffering = 0;
            }

        } else if (h->value.len == 3) {
            c0 = rap_tolower(h->value.data[0]);
            c1 = rap_tolower(h->value.data[1]);
            c2 = rap_tolower(h->value.data[2]);

            if (c0 == 'y' && c1 == 'e' && c2 == 's') {
                u->buffering = 1;
            }
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_charset(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    if (r->upstream->conf->ignore_headers & RAP_HTTP_UPSTREAM_IGN_XA_CHARSET) {
        return RAP_OK;
    }

    r->headers_out.override_charset = &h->value;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_connection(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    r->upstream->headers_in.connection = h;

    if (rap_strlcasestrn(h->value.data, h->value.data + h->value.len,
                         (u_char *) "close", 5 - 1)
        != NULL)
    {
        r->upstream->headers_in.connection_close = 1;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_transfer_encoding(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset)
{
    r->upstream->headers_in.transfer_encoding = h;

    if (rap_strlcasestrn(h->value.data, h->value.data + h->value.len,
                         (u_char *) "chunked", 7 - 1)
        != NULL)
    {
        r->upstream->headers_in.chunked = 1;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_process_vary(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset)
{
    rap_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.vary = h;

#if (RAP_HTTP_CACHE)

    if (u->conf->ignore_headers & RAP_HTTP_UPSTREAM_IGN_VARY) {
        return RAP_OK;
    }

    if (r->cache == NULL) {
        return RAP_OK;
    }

    if (h->value.len > RAP_HTTP_CACHE_VARY_LEN
        || (h->value.len == 1 && h->value.data[0] == '*'))
    {
        u->cacheable = 0;
    }

    r->cache->vary = h->value;

#endif

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_copy_header_line(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_table_elt_t  *ho, **ph;

    ho = rap_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RAP_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (rap_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_copy_multi_header_lines(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset)
{
    rap_array_t      *pa;
    rap_table_elt_t  *ho, **ph;

    pa = (rap_array_t *) ((char *) &r->headers_out + offset);

    if (pa->elts == NULL) {
        if (rap_array_init(pa, r->pool, 2, sizeof(rap_table_elt_t *)) != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    ho = rap_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RAP_ERROR;
    }

    *ho = *h;

    ph = rap_array_push(pa);
    if (ph == NULL) {
        return RAP_ERROR;
    }

    *ph = ho;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_copy_content_type(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
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
            return RAP_OK;
        }

        if (rap_strncasecmp(p, (u_char *) "charset=", 8) != 0) {
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

        return RAP_OK;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_copy_last_modified(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_table_elt_t  *ho;

    ho = rap_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RAP_ERROR;
    }

    *ho = *h;

    r->headers_out.last_modified = ho;
    r->headers_out.last_modified_time =
                                    r->upstream->headers_in.last_modified_time;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_rewrite_location(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_int_t         rc;
    rap_table_elt_t  *ho;

    ho = rap_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RAP_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_redirect) {
        rc = r->upstream->rewrite_redirect(r, ho, 0);

        if (rc == RAP_DECLINED) {
            return RAP_OK;
        }

        if (rc == RAP_OK) {
            r->headers_out.location = ho;

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten location: \"%V\"", &ho->value);
        }

        return rc;
    }

    if (ho->value.data[0] != '/') {
        r->headers_out.location = ho;
    }

    /*
     * we do not set r->headers_out.location here to avoid handling
     * relative redirects in rap_http_header_filter()
     */

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_rewrite_refresh(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    u_char           *p;
    rap_int_t         rc;
    rap_table_elt_t  *ho;

    ho = rap_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RAP_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_redirect) {

        p = rap_strcasestrn(ho->value.data, "url=", 4 - 1);

        if (p) {
            rc = r->upstream->rewrite_redirect(r, ho, p + 4 - ho->value.data);

        } else {
            return RAP_OK;
        }

        if (rc == RAP_DECLINED) {
            return RAP_OK;
        }

        if (rc == RAP_OK) {
            r->headers_out.refresh = ho;

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten refresh: \"%V\"", &ho->value);
        }

        return rc;
    }

    r->headers_out.refresh = ho;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_rewrite_set_cookie(rap_http_request_t *r, rap_table_elt_t *h,
    rap_uint_t offset)
{
    rap_int_t         rc;
    rap_table_elt_t  *ho;

    ho = rap_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RAP_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_cookie) {
        rc = r->upstream->rewrite_cookie(r, ho);

        if (rc == RAP_DECLINED) {
            return RAP_OK;
        }

#if (RAP_DEBUG)
        if (rc == RAP_OK) {
            rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten cookie: \"%V\"", &ho->value);
        }
#endif

        return rc;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_copy_allow_ranges(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset)
{
    rap_table_elt_t  *ho;

    if (r->upstream->conf->force_ranges) {
        return RAP_OK;
    }

#if (RAP_HTTP_CACHE)

    if (r->cached) {
        r->allow_ranges = 1;
        return RAP_OK;
    }

    if (r->upstream->cacheable) {
        r->allow_ranges = 1;
        r->single_range = 1;
        return RAP_OK;
    }

#endif

    ho = rap_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RAP_ERROR;
    }

    *ho = *h;

    r->headers_out.accept_ranges = ho;

    return RAP_OK;
}


#if (RAP_HTTP_GZIP)

static rap_int_t
rap_http_upstream_copy_content_encoding(rap_http_request_t *r,
    rap_table_elt_t *h, rap_uint_t offset)
{
    rap_table_elt_t  *ho;

    ho = rap_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return RAP_ERROR;
    }

    *ho = *h;

    r->headers_out.content_encoding = ho;

    return RAP_OK;
}

#endif


static rap_int_t
rap_http_upstream_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_upstream_vars; v->name.len; v++) {
        var = rap_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_addr_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    rap_uint_t                  i;
    rap_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RAP_OK;
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

    p = rap_pnalloc(r->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->data = p;

    i = 0;

    for ( ;; ) {
        if (state[i].peer) {
            p = rap_cpymem(p, state[i].peer->data, state[i].peer->len);
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

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_status_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    rap_uint_t                  i;
    rap_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    len = r->upstream_states->nelts * (3 + 2);

    p = rap_pnalloc(r->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {
        if (state[i].status) {
            p = rap_sprintf(p, "%ui", state[i].status);

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

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_response_time_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    rap_uint_t                  i;
    rap_msec_int_t              ms;
    rap_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    len = r->upstream_states->nelts * (RAP_TIME_T_LEN + 4 + 2);

    p = rap_pnalloc(r->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
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
            ms = rap_max(ms, 0);
            p = rap_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

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

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_response_length_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    rap_uint_t                  i;
    rap_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    len = r->upstream_states->nelts * (RAP_OFF_T_LEN + 2);

    p = rap_pnalloc(r->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            p = rap_sprintf(p, "%O", state[i].bytes_received);

        } else if (data == 2) {
            p = rap_sprintf(p, "%O", state[i].bytes_sent);

        } else {
            p = rap_sprintf(p, "%O", state[i].response_length);
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

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_header_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    return rap_http_variable_unknown_header(v, (rap_str_t *) data,
                                         &r->upstream->headers_in.headers.part,
                                         sizeof("upstream_http_") - 1);
}


static rap_int_t
rap_http_upstream_trailer_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    return rap_http_variable_unknown_header(v, (rap_str_t *) data,
                                        &r->upstream->headers_in.trailers.part,
                                        sizeof("upstream_trailer_") - 1);
}


static rap_int_t
rap_http_upstream_cookie_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_str_t  *name = (rap_str_t *) data;

    rap_str_t   cookie, s;

    if (r->upstream == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    s.len = name->len - (sizeof("upstream_cookie_") - 1);
    s.data = name->data + sizeof("upstream_cookie_") - 1;

    if (rap_http_parse_set_cookie_lines(&r->upstream->headers_in.cookies,
                                        &s, &cookie)
        == RAP_DECLINED)
    {
        v->not_found = 1;
        return RAP_OK;
    }

    v->len = cookie.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cookie.data;

    return RAP_OK;
}


#if (RAP_HTTP_CACHE)

static rap_int_t
rap_http_upstream_cache_status(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_uint_t  n;

    if (r->upstream == NULL || r->upstream->cache_status == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    n = r->upstream->cache_status - 1;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = rap_http_cache_status[n].len;
    v->data = rap_http_cache_status[n].data;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_cache_last_modified(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->upstream == NULL
        || !r->upstream->conf->cache_revalidate
        || r->upstream->cache_status != RAP_HTTP_CACHE_EXPIRED
        || r->cache->last_modified == -1)
    {
        v->not_found = 1;
        return RAP_OK;
    }

    p = rap_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_http_time(p, r->cache->last_modified) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_http_upstream_cache_etag(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL
        || !r->upstream->conf->cache_revalidate
        || r->upstream->cache_status != RAP_HTTP_CACHE_EXPIRED
        || r->cache->etag.len == 0)
    {
        v->not_found = 1;
        return RAP_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = r->cache->etag.len;
    v->data = r->cache->etag.data;

    return RAP_OK;
}

#endif


static char *
rap_http_upstream(rap_conf_t *cf, rap_command_t *cmd, void *dummy)
{
    char                          *rv;
    void                          *mconf;
    rap_str_t                     *value;
    rap_url_t                      u;
    rap_uint_t                     m;
    rap_conf_t                     pcf;
    rap_http_module_t             *module;
    rap_http_conf_ctx_t           *ctx, *http_ctx;
    rap_http_upstream_srv_conf_t  *uscf;

    rap_memzero(&u, sizeof(rap_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    uscf = rap_http_upstream_add(cf, &u, RAP_HTTP_UPSTREAM_CREATE
                                         |RAP_HTTP_UPSTREAM_WEIGHT
                                         |RAP_HTTP_UPSTREAM_MAX_CONNS
                                         |RAP_HTTP_UPSTREAM_MAX_FAILS
                                         |RAP_HTTP_UPSTREAM_FAIL_TIMEOUT
                                         |RAP_HTTP_UPSTREAM_DOWN
                                         |RAP_HTTP_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return RAP_CONF_ERROR;
    }


    ctx = rap_pcalloc(cf->pool, sizeof(rap_http_conf_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = rap_pcalloc(cf->pool, sizeof(void *) * rap_http_max_module);
    if (ctx->srv_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    ctx->srv_conf[rap_http_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;


    /* the upstream{}'s loc_conf */

    ctx->loc_conf = rap_pcalloc(cf->pool, sizeof(void *) * rap_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RAP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return RAP_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return RAP_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    uscf->servers = rap_array_create(cf->pool, 4,
                                     sizeof(rap_http_upstream_server_t));
    if (uscf->servers == NULL) {
        return RAP_CONF_ERROR;
    }


    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RAP_HTTP_UPS_CONF;

    rv = rap_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != RAP_CONF_OK) {
        return rv;
    }

    if (uscf->servers->nelts == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return RAP_CONF_ERROR;
    }

    return rv;
}


static char *
rap_http_upstream_server(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_upstream_srv_conf_t  *uscf = conf;

    time_t                       fail_timeout;
    rap_str_t                   *value, s;
    rap_url_t                    u;
    rap_int_t                    weight, max_conns, max_fails;
    rap_uint_t                   i;
    rap_http_upstream_server_t  *us;

    us = rap_array_push(uscf->servers);
    if (us == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(us, sizeof(rap_http_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (rap_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & RAP_HTTP_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = rap_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == RAP_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "max_conns=", 10) == 0) {

            if (!(uscf->flags & RAP_HTTP_UPSTREAM_MAX_CONNS)) {
                goto not_supported;
            }

            max_conns = rap_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == RAP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & RAP_HTTP_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = rap_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == RAP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & RAP_HTTP_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = rap_parse_time(&s, 1);

            if (fail_timeout == (time_t) RAP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rap_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & RAP_HTTP_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (rap_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & RAP_HTTP_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    rap_memzero(&u, sizeof(rap_url_t));

    u.url = value[1];
    u.default_port = 80;

    if (rap_parse_url(cf->pool, &u) != RAP_OK) {
        if (u.err) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return RAP_CONF_ERROR;
    }

    us->name = u.url;
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_conns = max_conns;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return RAP_CONF_OK;

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return RAP_CONF_ERROR;

not_supported:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return RAP_CONF_ERROR;
}


rap_http_upstream_srv_conf_t *
rap_http_upstream_add(rap_conf_t *cf, rap_url_t *u, rap_uint_t flags)
{
    rap_uint_t                      i;
    rap_http_upstream_server_t     *us;
    rap_http_upstream_srv_conf_t   *uscf, **uscfp;
    rap_http_upstream_main_conf_t  *umcf;

    if (!(flags & RAP_HTTP_UPSTREAM_CREATE)) {

        if (rap_parse_url(cf->pool, u) != RAP_OK) {
            if (u->err) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = rap_http_conf_get_module_main_conf(cf, rap_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || rap_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & RAP_HTTP_UPSTREAM_CREATE)
             && (uscfp[i]->flags & RAP_HTTP_UPSTREAM_CREATE))
        {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & RAP_HTTP_UPSTREAM_CREATE) && !u->no_port) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & RAP_HTTP_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
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

        if (flags & RAP_HTTP_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
            uscfp[i]->port = 0;
        }

        return uscfp[i];
    }

    uscf = rap_pcalloc(cf->pool, sizeof(rap_http_upstream_srv_conf_t));
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
        uscf->servers = rap_array_create(cf->pool, 1,
                                         sizeof(rap_http_upstream_server_t));
        if (uscf->servers == NULL) {
            return NULL;
        }

        us = rap_array_push(uscf->servers);
        if (us == NULL) {
            return NULL;
        }

        rap_memzero(us, sizeof(rap_http_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    uscfp = rap_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


char *
rap_http_upstream_bind_set_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    rap_int_t                           rc;
    rap_str_t                          *value;
    rap_http_complex_value_t            cv;
    rap_http_upstream_local_t         **plocal, *local;
    rap_http_compile_complex_value_t    ccv;

    plocal = (rap_http_upstream_local_t **) (p + cmd->offset);

    if (*plocal != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2 && rap_strcmp(value[1].data, "off") == 0) {
        *plocal = NULL;
        return RAP_CONF_OK;
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    local = rap_pcalloc(cf->pool, sizeof(rap_http_upstream_local_t));
    if (local == NULL) {
        return RAP_CONF_ERROR;
    }

    *plocal = local;

    if (cv.lengths) {
        local->value = rap_palloc(cf->pool, sizeof(rap_http_complex_value_t));
        if (local->value == NULL) {
            return RAP_CONF_ERROR;
        }

        *local->value = cv;

    } else {
        local->addr = rap_palloc(cf->pool, sizeof(rap_addr_t));
        if (local->addr == NULL) {
            return RAP_CONF_ERROR;
        }

        rc = rap_parse_addr_port(cf->pool, local->addr, value[1].data,
                                 value[1].len);

        switch (rc) {
        case RAP_OK:
            local->addr->name = value[1];
            break;

        case RAP_DECLINED:
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid address \"%V\"", &value[1]);
            /* fall through */

        default:
            return RAP_CONF_ERROR;
        }
    }

    if (cf->args->nelts > 2) {
        if (rap_strcmp(value[2].data, "transparent") == 0) {
#if (RAP_HAVE_TRANSPARENT_PROXY)
            rap_core_conf_t  *ccf;

            ccf = (rap_core_conf_t *) rap_get_conf(cf->cycle->conf_ctx,
                                                   rap_core_module);

            ccf->transparent = 1;
            local->transparent = 1;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "transparent proxying is not supported "
                               "on this platform, ignored");
#endif
        } else {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_upstream_set_local(rap_http_request_t *r, rap_http_upstream_t *u,
    rap_http_upstream_local_t *local)
{
    rap_int_t    rc;
    rap_str_t    val;
    rap_addr_t  *addr;

    if (local == NULL) {
        u->peer.local = NULL;
        return RAP_OK;
    }

#if (RAP_HAVE_TRANSPARENT_PROXY)
    u->peer.transparent = local->transparent;
#endif

    if (local->value == NULL) {
        u->peer.local = local->addr;
        return RAP_OK;
    }

    if (rap_http_complex_value(r, local->value, &val) != RAP_OK) {
        return RAP_ERROR;
    }

    if (val.len == 0) {
        return RAP_OK;
    }

    addr = rap_palloc(r->pool, sizeof(rap_addr_t));
    if (addr == NULL) {
        return RAP_ERROR;
    }

    rc = rap_parse_addr_port(r->pool, addr, val.data, val.len);
    if (rc == RAP_ERROR) {
        return RAP_ERROR;
    }

    if (rc != RAP_OK) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        return RAP_OK;
    }

    addr->name = val;
    u->peer.local = addr;

    return RAP_OK;
}


char *
rap_http_upstream_param_set_slot(rap_conf_t *cf, rap_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    rap_str_t                   *value;
    rap_array_t                **a;
    rap_http_upstream_param_t   *param;

    a = (rap_array_t **) (p + cmd->offset);

    if (*a == NULL) {
        *a = rap_array_create(cf->pool, 4, sizeof(rap_http_upstream_param_t));
        if (*a == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    param = rap_array_push(*a);
    if (param == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    param->key = value[1];
    param->value = value[2];
    param->skip_empty = 0;

    if (cf->args->nelts == 4) {
        if (rap_strcmp(value[3].data, "if_not_empty") != 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return RAP_CONF_ERROR;
        }

        param->skip_empty = 1;
    }

    return RAP_CONF_OK;
}


rap_int_t
rap_http_upstream_hide_headers_hash(rap_conf_t *cf,
    rap_http_upstream_conf_t *conf, rap_http_upstream_conf_t *prev,
    rap_str_t *default_hide_headers, rap_hash_init_t *hash)
{
    rap_str_t       *h;
    rap_uint_t       i, j;
    rap_array_t      hide_headers;
    rap_hash_key_t  *hk;

    if (conf->hide_headers == RAP_CONF_UNSET_PTR
        && conf->pass_headers == RAP_CONF_UNSET_PTR)
    {
        conf->hide_headers = prev->hide_headers;
        conf->pass_headers = prev->pass_headers;

        conf->hide_headers_hash = prev->hide_headers_hash;

        if (conf->hide_headers_hash.buckets) {
            return RAP_OK;
        }

    } else {
        if (conf->hide_headers == RAP_CONF_UNSET_PTR) {
            conf->hide_headers = prev->hide_headers;
        }

        if (conf->pass_headers == RAP_CONF_UNSET_PTR) {
            conf->pass_headers = prev->pass_headers;
        }
    }

    if (rap_array_init(&hide_headers, cf->temp_pool, 4, sizeof(rap_hash_key_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    for (h = default_hide_headers; h->len; h++) {
        hk = rap_array_push(&hide_headers);
        if (hk == NULL) {
            return RAP_ERROR;
        }

        hk->key = *h;
        hk->key_hash = rap_hash_key_lc(h->data, h->len);
        hk->value = (void *) 1;
    }

    if (conf->hide_headers != RAP_CONF_UNSET_PTR) {

        h = conf->hide_headers->elts;

        for (i = 0; i < conf->hide_headers->nelts; i++) {

            hk = hide_headers.elts;

            for (j = 0; j < hide_headers.nelts; j++) {
                if (rap_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    goto exist;
                }
            }

            hk = rap_array_push(&hide_headers);
            if (hk == NULL) {
                return RAP_ERROR;
            }

            hk->key = h[i];
            hk->key_hash = rap_hash_key_lc(h[i].data, h[i].len);
            hk->value = (void *) 1;

        exist:

            continue;
        }
    }

    if (conf->pass_headers != RAP_CONF_UNSET_PTR) {

        h = conf->pass_headers->elts;
        hk = hide_headers.elts;

        for (i = 0; i < conf->pass_headers->nelts; i++) {
            for (j = 0; j < hide_headers.nelts; j++) {

                if (hk[j].key.data == NULL) {
                    continue;
                }

                if (rap_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    hk[j].key.data = NULL;
                    break;
                }
            }
        }
    }

    hash->hash = &conf->hide_headers_hash;
    hash->key = rap_hash_key_lc;
    hash->pool = cf->pool;
    hash->temp_pool = NULL;

    if (rap_hash_init(hash, hide_headers.elts, hide_headers.nelts) != RAP_OK) {
        return RAP_ERROR;
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

    return RAP_OK;
}


static void *
rap_http_upstream_create_main_conf(rap_conf_t *cf)
{
    rap_http_upstream_main_conf_t  *umcf;

    umcf = rap_pcalloc(cf->pool, sizeof(rap_http_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (rap_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(rap_http_upstream_srv_conf_t *))
        != RAP_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
rap_http_upstream_init_main_conf(rap_conf_t *cf, void *conf)
{
    rap_http_upstream_main_conf_t  *umcf = conf;

    rap_uint_t                      i;
    rap_array_t                     headers_in;
    rap_hash_key_t                 *hk;
    rap_hash_init_t                 hash;
    rap_http_upstream_init_pt       init;
    rap_http_upstream_header_t     *header;
    rap_http_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream ? uscfp[i]->peer.init_upstream:
                                            rap_http_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }


    /* upstream_headers_in_hash */

    if (rap_array_init(&headers_in, cf->temp_pool, 32, sizeof(rap_hash_key_t))
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    for (header = rap_http_upstream_headers_in; header->name.len; header++) {
        hk = rap_array_push(&headers_in);
        if (hk == NULL) {
            return RAP_CONF_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = rap_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &umcf->headers_in_hash;
    hash.key = rap_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = rap_align(64, rap_cacheline_size);
    hash.name = "upstream_headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (rap_hash_init(&hash, headers_in.elts, headers_in.nelts) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
