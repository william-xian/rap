
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */

#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static char *rap_http_flv(rap_conf_t *cf, rap_command_t *cmd, void *conf);

static rap_command_t  rap_http_flv_commands[] = {

    { rap_string("flv"),
      RAP_HTTP_LOC_CONF|RAP_CONF_NOARGS,
      rap_http_flv,
      0,
      0,
      NULL },

      rap_null_command
};


static u_char  rap_flv_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";


static rap_http_module_t  rap_http_flv_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


rap_module_t  rap_http_flv_module = {
    RAP_MODULE_V1,
    &rap_http_flv_module_ctx,      /* module context */
    rap_http_flv_commands,         /* module directives */
    RAP_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_int_t
rap_http_flv_handler(rap_http_request_t *r)
{
    u_char                    *last;
    off_t                      start, len;
    size_t                     root;
    rap_int_t                  rc;
    rap_uint_t                 level, i;
    rap_str_t                  path, value;
    rap_log_t                 *log;
    rap_buf_t                 *b;
    rap_chain_t                out[2];
    rap_open_file_info_t       of;
    rap_http_core_loc_conf_t  *clcf;

    if (!(r->method & (RAP_HTTP_GET|RAP_HTTP_HEAD))) {
        return RAP_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return RAP_DECLINED;
    }

    rc = rap_http_discard_request_body(r);

    if (rc != RAP_OK) {
        return rc;
    }

    last = rap_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%V\"", &path);

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    rap_memzero(&of, sizeof(rap_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (rap_http_set_disable_symlinks(r, clcf, &path, &of) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rap_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != RAP_OK)
    {
        switch (of.err) {

        case 0:
            return RAP_HTTP_INTERNAL_SERVER_ERROR;

        case RAP_ENOENT:
        case RAP_ENOTDIR:
        case RAP_ENAMETOOLONG:

            level = RAP_LOG_ERR;
            rc = RAP_HTTP_NOT_FOUND;
            break;

        case RAP_EACCES:
#if (RAP_HAVE_OPENAT)
        case RAP_EMLINK:
        case RAP_ELOOP:
#endif

            level = RAP_LOG_ERR;
            rc = RAP_HTTP_FORBIDDEN;
            break;

        default:

            level = RAP_LOG_CRIT;
            rc = RAP_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != RAP_HTTP_NOT_FOUND || clcf->log_not_found) {
            rap_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (rap_close_file(of.fd) == RAP_FILE_ERROR) {
            rap_log_error(RAP_LOG_ALERT, log, rap_errno,
                          rap_close_file_n " \"%s\" failed", path.data);
        }

        return RAP_DECLINED;
    }

    r->root_tested = !r->error_page;

    start = 0;
    len = of.size;
    i = 1;

    if (r->args.len) {

        if (rap_http_arg(r, (u_char *) "start", 5, &value) == RAP_OK) {

            start = rap_atoof(value.data, value.len);

            if (start == RAP_ERROR || start >= len) {
                start = 0;
            }

            if (start) {
                len = sizeof(rap_flv_header) - 1 + len - start;
                i = 0;
            }
        }
    }

    log->action = "sending flv to client";

    r->headers_out.status = RAP_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.last_modified_time = of.mtime;

    if (rap_http_set_etag(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rap_http_set_content_type(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (i == 0) {
        b = rap_calloc_buf(r->pool);
        if (b == NULL) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->pos = rap_flv_header;
        b->last = rap_flv_header + sizeof(rap_flv_header) - 1;
        b->memory = 1;

        out[0].buf = b;
        out[0].next = &out[1];
    }


    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = rap_pcalloc(r->pool, sizeof(rap_file_t));
    if (b->file == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allow_ranges = 1;

    rc = rap_http_send_header(r);

    if (rc == RAP_ERROR || rc > RAP_OK || r->header_only) {
        return rc;
    }

    b->file_pos = start;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out[1].buf = b;
    out[1].next = NULL;

    return rap_http_output_filter(r, &out[i]);
}


static char *
rap_http_flv(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);
    clcf->handler = rap_http_flv_handler;

    return RAP_CONF_OK;
}
