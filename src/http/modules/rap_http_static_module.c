
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static rap_int_t rap_http_static_handler(rap_http_request_t *r);
static rap_int_t rap_http_static_init(rap_conf_t *cf);


static rap_http_module_t  rap_http_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_static_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_static_module = {
    RAP_MODULE_V1,
    &rap_http_static_module_ctx,           /* module context */
    NULL,                                  /* module directives */
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


static rap_int_t
rap_http_static_handler(rap_http_request_t *r)
{
    u_char                    *last, *location;
    size_t                     root, len;
    rap_str_t                  path;
    rap_int_t                  rc;
    rap_uint_t                 level;
    rap_log_t                 *log;
    rap_buf_t                 *b;
    rap_chain_t                out;
    rap_open_file_info_t       of;
    rap_http_core_loc_conf_t  *clcf;

    if (!(r->method & (RAP_HTTP_GET|RAP_HTTP_HEAD|RAP_HTTP_POST))) {
        return RAP_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return RAP_DECLINED;
    }

    log = r->connection->log;

    /*
     * rap_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = rap_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

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

    r->root_tested = !r->error_page;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {

        rap_log_debug0(RAP_LOG_DEBUG_HTTP, log, 0, "http dir");

        rap_http_clear_location(r);

        r->headers_out.location = rap_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        len = r->uri.len + 1;

        if (!clcf->alias && r->args.len == 0) {
            location = path.data + root;

            *last = '/';

        } else {
            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = rap_pnalloc(r->pool, len);
            if (location == NULL) {
                rap_http_clear_location(r);
                return RAP_HTTP_INTERNAL_SERVER_ERROR;
            }

            last = rap_copy(location, r->uri.data, r->uri.len);

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                rap_memcpy(++last, r->args.data, r->args.len);
            }
        }

        r->headers_out.location->hash = 1;
        rap_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return RAP_HTTP_MOVED_PERMANENTLY;
    }

#if !(RAP_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        rap_log_error(RAP_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return RAP_HTTP_NOT_FOUND;
    }

#endif

    if (r->method == RAP_HTTP_POST) {
        return RAP_HTTP_NOT_ALLOWED;
    }

    rc = rap_http_discard_request_body(r);

    if (rc != RAP_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = RAP_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (rap_http_set_etag(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rap_http_set_content_type(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return rap_http_send_header(r);
    }

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = rap_calloc_buf(r->pool);
    if (b == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = rap_pcalloc(r->pool, sizeof(rap_file_t));
    if (b->file == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = rap_http_send_header(r);

    if (rc == RAP_ERROR || rc > RAP_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return rap_http_output_filter(r, &out);
}


static rap_int_t
rap_http_static_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_static_handler;

    return RAP_OK;
}
