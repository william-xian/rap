
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */

#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static char *rp_http_flv(rp_conf_t *cf, rp_command_t *cmd, void *conf);

static rp_command_t  rp_http_flv_commands[] = {

    { rp_string("flv"),
      RP_HTTP_LOC_CONF|RP_CONF_NOARGS,
      rp_http_flv,
      0,
      0,
      NULL },

      rp_null_command
};


static u_char  rp_flv_header[] = "FLV\x1\x5\0\0\0\x9\0\0\0\0";


static rp_http_module_t  rp_http_flv_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


rp_module_t  rp_http_flv_module = {
    RP_MODULE_V1,
    &rp_http_flv_module_ctx,      /* module context */
    rp_http_flv_commands,         /* module directives */
    RP_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_int_t
rp_http_flv_handler(rp_http_request_t *r)
{
    u_char                    *last;
    off_t                      start, len;
    size_t                     root;
    rp_int_t                  rc;
    rp_uint_t                 level, i;
    rp_str_t                  path, value;
    rp_log_t                 *log;
    rp_buf_t                 *b;
    rp_chain_t                out[2];
    rp_open_file_info_t       of;
    rp_http_core_loc_conf_t  *clcf;

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD))) {
        return RP_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return RP_DECLINED;
    }

    rc = rp_http_discard_request_body(r);

    if (rc != RP_OK) {
        return rc;
    }

    last = rp_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;

    path.len = last - path.data;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, log, 0,
                   "http flv filename: \"%V\"", &path);

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    rp_memzero(&of, sizeof(rp_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (rp_http_set_disable_symlinks(r, clcf, &path, &of) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != RP_OK)
    {
        switch (of.err) {

        case 0:
            return RP_HTTP_INTERNAL_SERVER_ERROR;

        case RP_ENOENT:
        case RP_ENOTDIR:
        case RP_ENAMETOOLONG:

            level = RP_LOG_ERR;
            rc = RP_HTTP_NOT_FOUND;
            break;

        case RP_EACCES:
#if (RP_HAVE_OPENAT)
        case RP_EMLINK:
        case RP_ELOOP:
#endif

            level = RP_LOG_ERR;
            rc = RP_HTTP_FORBIDDEN;
            break;

        default:

            level = RP_LOG_CRIT;
            rc = RP_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != RP_HTTP_NOT_FOUND || clcf->log_not_found) {
            rp_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    if (!of.is_file) {

        if (rp_close_file(of.fd) == RP_FILE_ERROR) {
            rp_log_error(RP_LOG_ALERT, log, rp_errno,
                          rp_close_file_n " \"%s\" failed", path.data);
        }

        return RP_DECLINED;
    }

    r->root_tested = !r->error_page;

    start = 0;
    len = of.size;
    i = 1;

    if (r->args.len) {

        if (rp_http_arg(r, (u_char *) "start", 5, &value) == RP_OK) {

            start = rp_atoof(value.data, value.len);

            if (start == RP_ERROR || start >= len) {
                start = 0;
            }

            if (start) {
                len = sizeof(rp_flv_header) - 1 + len - start;
                i = 0;
            }
        }
    }

    log->action = "sending flv to client";

    r->headers_out.status = RP_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.last_modified_time = of.mtime;

    if (rp_http_set_etag(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_http_set_content_type(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (i == 0) {
        b = rp_calloc_buf(r->pool);
        if (b == NULL) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->pos = rp_flv_header;
        b->last = rp_flv_header + sizeof(rp_flv_header) - 1;
        b->memory = 1;

        out[0].buf = b;
        out[0].next = &out[1];
    }


    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = rp_pcalloc(r->pool, sizeof(rp_file_t));
    if (b->file == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->allow_ranges = 1;

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
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

    return rp_http_output_filter(r, &out[i]);
}


static char *
rp_http_flv(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);
    clcf->handler = rp_http_flv_handler;

    return RP_CONF_OK;
}
