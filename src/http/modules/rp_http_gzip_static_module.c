
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_GZIP_STATIC_OFF     0
#define RP_HTTP_GZIP_STATIC_ON      1
#define RP_HTTP_GZIP_STATIC_ALWAYS  2


typedef struct {
    rp_uint_t  enable;
} rp_http_gzip_static_conf_t;


static rp_int_t rp_http_gzip_static_handler(rp_http_request_t *r);
static void *rp_http_gzip_static_create_conf(rp_conf_t *cf);
static char *rp_http_gzip_static_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static rp_int_t rp_http_gzip_static_init(rp_conf_t *cf);


static rp_conf_enum_t  rp_http_gzip_static[] = {
    { rp_string("off"), RP_HTTP_GZIP_STATIC_OFF },
    { rp_string("on"), RP_HTTP_GZIP_STATIC_ON },
    { rp_string("always"), RP_HTTP_GZIP_STATIC_ALWAYS },
    { rp_null_string, 0 }
};


static rp_command_t  rp_http_gzip_static_commands[] = {

    { rp_string("gzip_static"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_gzip_static_conf_t, enable),
      &rp_http_gzip_static },

      rp_null_command
};


static rp_http_module_t  rp_http_gzip_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_gzip_static_init,             /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_gzip_static_create_conf,      /* create location configuration */
    rp_http_gzip_static_merge_conf        /* merge location configuration */
};


rp_module_t  rp_http_gzip_static_module = {
    RP_MODULE_V1,
    &rp_http_gzip_static_module_ctx,      /* module context */
    rp_http_gzip_static_commands,         /* module directives */
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
rp_http_gzip_static_handler(rp_http_request_t *r)
{
    u_char                       *p;
    size_t                        root;
    rp_str_t                     path;
    rp_int_t                     rc;
    rp_uint_t                    level;
    rp_log_t                    *log;
    rp_buf_t                    *b;
    rp_chain_t                   out;
    rp_table_elt_t              *h;
    rp_open_file_info_t          of;
    rp_http_core_loc_conf_t     *clcf;
    rp_http_gzip_static_conf_t  *gzcf;

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD))) {
        return RP_DECLINED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return RP_DECLINED;
    }

    gzcf = rp_http_get_module_loc_conf(r, rp_http_gzip_static_module);

    if (gzcf->enable == RP_HTTP_GZIP_STATIC_OFF) {
        return RP_DECLINED;
    }

    if (gzcf->enable == RP_HTTP_GZIP_STATIC_ON) {
        rc = rp_http_gzip_ok(r);

    } else {
        /* always */
        rc = RP_OK;
    }

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (!clcf->gzip_vary && rc != RP_OK) {
        return RP_DECLINED;
    }

    log = r->connection->log;

    p = rp_http_map_uri_to_path(r, &path, &root, sizeof(".gz") - 1);
    if (p == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    *p++ = '.';
    *p++ = 'g';
    *p++ = 'z';
    *p = '\0';

    path.len = p - path.data;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

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

            return RP_DECLINED;

        case RP_EACCES:
#if (RP_HAVE_OPENAT)
        case RP_EMLINK:
        case RP_ELOOP:
#endif

            level = RP_LOG_ERR;
            break;

        default:

            level = RP_LOG_CRIT;
            break;
        }

        rp_log_error(level, log, of.err,
                      "%s \"%s\" failed", of.failed, path.data);

        return RP_DECLINED;
    }

    if (gzcf->enable == RP_HTTP_GZIP_STATIC_ON) {
        r->gzip_vary = 1;

        if (rc != RP_OK) {
            return RP_DECLINED;
        }
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, log, 0, "http dir");
        return RP_DECLINED;
    }

#if !(RP_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        rp_log_error(RP_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return RP_HTTP_NOT_FOUND;
    }

#endif

    r->root_tested = !r->error_page;

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

    h = rp_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    h->hash = 1;
    rp_str_set(&h->key, "Content-Encoding");
    rp_str_set(&h->value, "gzip");
    r->headers_out.content_encoding = h;

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

    b->in_file = b->file_last ? 1 : 0;
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return rp_http_output_filter(r, &out);
}


static void *
rp_http_gzip_static_create_conf(rp_conf_t *cf)
{
    rp_http_gzip_static_conf_t  *conf;

    conf = rp_palloc(cf->pool, sizeof(rp_http_gzip_static_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = RP_CONF_UNSET_UINT;

    return conf;
}


static char *
rp_http_gzip_static_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_gzip_static_conf_t *prev = parent;
    rp_http_gzip_static_conf_t *conf = child;

    rp_conf_merge_uint_value(conf->enable, prev->enable,
                              RP_HTTP_GZIP_STATIC_OFF);

    return RP_CONF_OK;
}


static rp_int_t
rp_http_gzip_static_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_gzip_static_handler;

    return RP_OK;
}
