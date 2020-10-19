
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_GZIP_STATIC_OFF     0
#define RAP_HTTP_GZIP_STATIC_ON      1
#define RAP_HTTP_GZIP_STATIC_ALWAYS  2


typedef struct {
    rap_uint_t  enable;
} rap_http_gzip_static_conf_t;


static rap_int_t rap_http_gzip_static_handler(rap_http_request_t *r);
static void *rap_http_gzip_static_create_conf(rap_conf_t *cf);
static char *rap_http_gzip_static_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static rap_int_t rap_http_gzip_static_init(rap_conf_t *cf);


static rap_conf_enum_t  rap_http_gzip_static[] = {
    { rap_string("off"), RAP_HTTP_GZIP_STATIC_OFF },
    { rap_string("on"), RAP_HTTP_GZIP_STATIC_ON },
    { rap_string("always"), RAP_HTTP_GZIP_STATIC_ALWAYS },
    { rap_null_string, 0 }
};


static rap_command_t  rap_http_gzip_static_commands[] = {

    { rap_string("gzip_static"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_gzip_static_conf_t, enable),
      &rap_http_gzip_static },

      rap_null_command
};


static rap_http_module_t  rap_http_gzip_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_gzip_static_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_gzip_static_create_conf,      /* create location configuration */
    rap_http_gzip_static_merge_conf        /* merge location configuration */
};


rap_module_t  rap_http_gzip_static_module = {
    RAP_MODULE_V1,
    &rap_http_gzip_static_module_ctx,      /* module context */
    rap_http_gzip_static_commands,         /* module directives */
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
rap_http_gzip_static_handler(rap_http_request_t *r)
{
    u_char                       *p;
    size_t                        root;
    rap_str_t                     path;
    rap_int_t                     rc;
    rap_uint_t                    level;
    rap_log_t                    *log;
    rap_buf_t                    *b;
    rap_chain_t                   out;
    rap_table_elt_t              *h;
    rap_open_file_info_t          of;
    rap_http_core_loc_conf_t     *clcf;
    rap_http_gzip_static_conf_t  *gzcf;

    if (!(r->method & (RAP_HTTP_GET|RAP_HTTP_HEAD))) {
        return RAP_DECLINED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return RAP_DECLINED;
    }

    gzcf = rap_http_get_module_loc_conf(r, rap_http_gzip_static_module);

    if (gzcf->enable == RAP_HTTP_GZIP_STATIC_OFF) {
        return RAP_DECLINED;
    }

    if (gzcf->enable == RAP_HTTP_GZIP_STATIC_ON) {
        rc = rap_http_gzip_ok(r);

    } else {
        /* always */
        rc = RAP_OK;
    }

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (!clcf->gzip_vary && rc != RAP_OK) {
        return RAP_DECLINED;
    }

    log = r->connection->log;

    p = rap_http_map_uri_to_path(r, &path, &root, sizeof(".gz") - 1);
    if (p == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    *p++ = '.';
    *p++ = 'g';
    *p++ = 'z';
    *p = '\0';

    path.len = p - path.data;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

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

            return RAP_DECLINED;

        case RAP_EACCES:
#if (RAP_HAVE_OPENAT)
        case RAP_EMLINK:
        case RAP_ELOOP:
#endif

            level = RAP_LOG_ERR;
            break;

        default:

            level = RAP_LOG_CRIT;
            break;
        }

        rap_log_error(level, log, of.err,
                      "%s \"%s\" failed", of.failed, path.data);

        return RAP_DECLINED;
    }

    if (gzcf->enable == RAP_HTTP_GZIP_STATIC_ON) {
        r->gzip_vary = 1;

        if (rc != RAP_OK) {
            return RAP_DECLINED;
        }
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, log, 0, "http dir");
        return RAP_DECLINED;
    }

#if !(RAP_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        rap_log_error(RAP_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return RAP_HTTP_NOT_FOUND;
    }

#endif

    r->root_tested = !r->error_page;

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

    h = rap_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    rap_str_set(&h->key, "Content-Encoding");
    rap_str_set(&h->value, "gzip");
    r->headers_out.content_encoding = h;

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

    b->in_file = b->file_last ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return rap_http_output_filter(r, &out);
}


static void *
rap_http_gzip_static_create_conf(rap_conf_t *cf)
{
    rap_http_gzip_static_conf_t  *conf;

    conf = rap_palloc(cf->pool, sizeof(rap_http_gzip_static_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = RAP_CONF_UNSET_UINT;

    return conf;
}


static char *
rap_http_gzip_static_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_gzip_static_conf_t *prev = parent;
    rap_http_gzip_static_conf_t *conf = child;

    rap_conf_merge_uint_value(conf->enable, prev->enable,
                              RAP_HTTP_GZIP_STATIC_OFF);

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_gzip_static_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_gzip_static_handler;

    return RAP_OK;
}
