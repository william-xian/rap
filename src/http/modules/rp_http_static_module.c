
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static rp_int_t rp_http_static_handler(rp_http_request_t *r);
static rp_int_t rp_http_static_init(rp_conf_t *cf);


static rp_http_module_t  rp_http_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_static_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_static_module = {
    RP_MODULE_V1,
    &rp_http_static_module_ctx,           /* module context */
    NULL,                                  /* module directives */
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


static rp_int_t
rp_http_static_handler(rp_http_request_t *r)
{
    u_char                    *last, *location;
    size_t                     root, len;
    rp_str_t                  path;
    rp_int_t                  rc;
    rp_uint_t                 level;
    rp_log_t                 *log;
    rp_buf_t                 *b;
    rp_chain_t                out;
    rp_open_file_info_t       of;
    rp_http_core_loc_conf_t  *clcf;

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD|RP_HTTP_POST))) {
        return RP_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return RP_DECLINED;
    }

    log = r->connection->log;

    /*
     * rp_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = rp_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

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

    r->root_tested = !r->error_page;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {

        rp_log_debug0(RP_LOG_DEBUG_HTTP, log, 0, "http dir");

        rp_http_clear_location(r);

        r->headers_out.location = rp_list_push(&r->headers_out.headers);
        if (r->headers_out.location == NULL) {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        len = r->uri.len + 1;

        if (!clcf->alias && r->args.len == 0) {
            location = path.data + root;

            *last = '/';

        } else {
            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = rp_pnalloc(r->pool, len);
            if (location == NULL) {
                rp_http_clear_location(r);
                return RP_HTTP_INTERNAL_SERVER_ERROR;
            }

            last = rp_copy(location, r->uri.data, r->uri.len);

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                rp_memcpy(++last, r->args.data, r->args.len);
            }
        }

        r->headers_out.location->hash = 1;
        rp_str_set(&r->headers_out.location->key, "Location");
        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return RP_HTTP_MOVED_PERMANENTLY;
    }

#if !(RP_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        rp_log_error(RP_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return RP_HTTP_NOT_FOUND;
    }

#endif

    if (r->method == RP_HTTP_POST) {
        return RP_HTTP_NOT_ALLOWED;
    }

    rc = rp_http_discard_request_body(r);

    if (rc != RP_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = RP_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (rp_http_set_etag(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_http_set_content_type(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return rp_http_send_header(r);
    }

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = rp_calloc_buf(r->pool);
    if (b == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = rp_pcalloc(r->pool, sizeof(rp_file_t));
    if (b->file == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = rp_http_send_header(r);

    if (rc == RP_ERROR || rc > RP_OK || r->header_only) {
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

    return rp_http_output_filter(r, &out);
}


static rp_int_t
rp_http_static_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_static_handler;

    return RP_OK;
}
