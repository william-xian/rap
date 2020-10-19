
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_str_t     before_body;
    rap_str_t     after_body;

    rap_hash_t    types;
    rap_array_t  *types_keys;
} rap_http_addition_conf_t;


typedef struct {
    rap_uint_t    before_body_sent;
} rap_http_addition_ctx_t;


static void *rap_http_addition_create_conf(rap_conf_t *cf);
static char *rap_http_addition_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static rap_int_t rap_http_addition_filter_init(rap_conf_t *cf);


static rap_command_t  rap_http_addition_commands[] = {

    { rap_string("add_before_body"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_addition_conf_t, before_body),
      NULL },

    { rap_string("add_after_body"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_addition_conf_t, after_body),
      NULL },

    { rap_string("addition_types"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_types_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_addition_conf_t, types_keys),
      &rap_http_html_default_types[0] },

      rap_null_command
};


static rap_http_module_t  rap_http_addition_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_addition_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_addition_create_conf,         /* create location configuration */
    rap_http_addition_merge_conf           /* merge location configuration */
};


rap_module_t  rap_http_addition_filter_module = {
    RAP_MODULE_V1,
    &rap_http_addition_filter_module_ctx,  /* module context */
    rap_http_addition_commands,            /* module directives */
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


static rap_http_output_header_filter_pt  rap_http_next_header_filter;
static rap_http_output_body_filter_pt    rap_http_next_body_filter;


static rap_int_t
rap_http_addition_header_filter(rap_http_request_t *r)
{
    rap_http_addition_ctx_t   *ctx;
    rap_http_addition_conf_t  *conf;

    if (r->headers_out.status != RAP_HTTP_OK || r != r->main) {
        return rap_http_next_header_filter(r);
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_addition_filter_module);

    if (conf->before_body.len == 0 && conf->after_body.len == 0) {
        return rap_http_next_header_filter(r);
    }

    if (rap_http_test_content_type(r, &conf->types) == NULL) {
        return rap_http_next_header_filter(r);
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_addition_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    rap_http_set_ctx(r, ctx, rap_http_addition_filter_module);

    rap_http_clear_content_length(r);
    rap_http_clear_accept_ranges(r);
    rap_http_weak_etag(r);

    r->preserve_body = 1;

    return rap_http_next_header_filter(r);
}


static rap_int_t
rap_http_addition_body_filter(rap_http_request_t *r, rap_chain_t *in)
{
    rap_int_t                  rc;
    rap_uint_t                 last;
    rap_chain_t               *cl;
    rap_http_request_t        *sr;
    rap_http_addition_ctx_t   *ctx;
    rap_http_addition_conf_t  *conf;

    if (in == NULL || r->header_only) {
        return rap_http_next_body_filter(r, in);
    }

    ctx = rap_http_get_module_ctx(r, rap_http_addition_filter_module);

    if (ctx == NULL) {
        return rap_http_next_body_filter(r, in);
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_addition_filter_module);

    if (!ctx->before_body_sent) {
        ctx->before_body_sent = 1;

        if (conf->before_body.len) {
            if (rap_http_subrequest(r, &conf->before_body, NULL, &sr, NULL, 0)
                != RAP_OK)
            {
                return RAP_ERROR;
            }
        }
    }

    if (conf->after_body.len == 0) {
        rap_http_set_ctx(r, NULL, rap_http_addition_filter_module);
        return rap_http_next_body_filter(r, in);
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

    rc = rap_http_next_body_filter(r, in);

    if (rc == RAP_ERROR || !last || conf->after_body.len == 0) {
        return rc;
    }

    if (rap_http_subrequest(r, &conf->after_body, NULL, &sr, NULL, 0)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    rap_http_set_ctx(r, NULL, rap_http_addition_filter_module);

    return rap_http_send_special(r, RAP_HTTP_LAST);
}


static rap_int_t
rap_http_addition_filter_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_addition_header_filter;

    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_addition_body_filter;

    return RAP_OK;
}


static void *
rap_http_addition_create_conf(rap_conf_t *cf)
{
    rap_http_addition_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_addition_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->before_body = { 0, NULL };
     *     conf->after_body = { 0, NULL };
     *     conf->types = { NULL };
     *     conf->types_keys = NULL;
     */

    return conf;
}


static char *
rap_http_addition_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_addition_conf_t *prev = parent;
    rap_http_addition_conf_t *conf = child;

    rap_conf_merge_str_value(conf->before_body, prev->before_body, "");
    rap_conf_merge_str_value(conf->after_body, prev->after_body, "");

    if (rap_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             rap_http_html_default_types)
        != RAP_OK)
    {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
