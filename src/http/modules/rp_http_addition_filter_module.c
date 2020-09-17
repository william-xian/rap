
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_str_t     before_body;
    rp_str_t     after_body;

    rp_hash_t    types;
    rp_array_t  *types_keys;
} rp_http_addition_conf_t;


typedef struct {
    rp_uint_t    before_body_sent;
} rp_http_addition_ctx_t;


static void *rp_http_addition_create_conf(rp_conf_t *cf);
static char *rp_http_addition_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static rp_int_t rp_http_addition_filter_init(rp_conf_t *cf);


static rp_command_t  rp_http_addition_commands[] = {

    { rp_string("add_before_body"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_addition_conf_t, before_body),
      NULL },

    { rp_string("add_after_body"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_addition_conf_t, after_body),
      NULL },

    { rp_string("addition_types"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_types_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_addition_conf_t, types_keys),
      &rp_http_html_default_types[0] },

      rp_null_command
};


static rp_http_module_t  rp_http_addition_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_addition_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_addition_create_conf,         /* create location configuration */
    rp_http_addition_merge_conf           /* merge location configuration */
};


rp_module_t  rp_http_addition_filter_module = {
    RP_MODULE_V1,
    &rp_http_addition_filter_module_ctx,  /* module context */
    rp_http_addition_commands,            /* module directives */
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


static rp_http_output_header_filter_pt  rp_http_next_header_filter;
static rp_http_output_body_filter_pt    rp_http_next_body_filter;


static rp_int_t
rp_http_addition_header_filter(rp_http_request_t *r)
{
    rp_http_addition_ctx_t   *ctx;
    rp_http_addition_conf_t  *conf;

    if (r->headers_out.status != RP_HTTP_OK || r != r->main) {
        return rp_http_next_header_filter(r);
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_addition_filter_module);

    if (conf->before_body.len == 0 && conf->after_body.len == 0) {
        return rp_http_next_header_filter(r);
    }

    if (rp_http_test_content_type(r, &conf->types) == NULL) {
        return rp_http_next_header_filter(r);
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_addition_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    rp_http_set_ctx(r, ctx, rp_http_addition_filter_module);

    rp_http_clear_content_length(r);
    rp_http_clear_accept_ranges(r);
    rp_http_weak_etag(r);

    r->preserve_body = 1;

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_addition_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_int_t                  rc;
    rp_uint_t                 last;
    rp_chain_t               *cl;
    rp_http_request_t        *sr;
    rp_http_addition_ctx_t   *ctx;
    rp_http_addition_conf_t  *conf;

    if (in == NULL || r->header_only) {
        return rp_http_next_body_filter(r, in);
    }

    ctx = rp_http_get_module_ctx(r, rp_http_addition_filter_module);

    if (ctx == NULL) {
        return rp_http_next_body_filter(r, in);
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_addition_filter_module);

    if (!ctx->before_body_sent) {
        ctx->before_body_sent = 1;

        if (conf->before_body.len) {
            if (rp_http_subrequest(r, &conf->before_body, NULL, &sr, NULL, 0)
                != RP_OK)
            {
                return RP_ERROR;
            }
        }
    }

    if (conf->after_body.len == 0) {
        rp_http_set_ctx(r, NULL, rp_http_addition_filter_module);
        return rp_http_next_body_filter(r, in);
    }

    last = 0;

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            cl->buf->last_buf = 0;
            cl->buf->last_in_chain = 1;
            cl->buf->sync = 1;
            last = 1;
        }
    }

    rc = rp_http_next_body_filter(r, in);

    if (rc == RP_ERROR || !last || conf->after_body.len == 0) {
        return rc;
    }

    if (rp_http_subrequest(r, &conf->after_body, NULL, &sr, NULL, 0)
        != RP_OK)
    {
        return RP_ERROR;
    }

    rp_http_set_ctx(r, NULL, rp_http_addition_filter_module);

    return rp_http_send_special(r, RP_HTTP_LAST);
}


static rp_int_t
rp_http_addition_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_addition_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_addition_body_filter;

    return RP_OK;
}


static void *
rp_http_addition_create_conf(rp_conf_t *cf)
{
    rp_http_addition_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_addition_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->before_body = { 0, NULL };
     *     conf->after_body = { 0, NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    return conf;
}


static char *
rp_http_addition_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_addition_conf_t *prev = parent;
    rp_http_addition_conf_t *conf = child;

    rp_conf_merge_str_value(conf->before_body, prev->before_body, "");
    rp_conf_merge_str_value(conf->after_body, prev->after_body, "");

    if (rp_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rp_http_html_default_types)
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
