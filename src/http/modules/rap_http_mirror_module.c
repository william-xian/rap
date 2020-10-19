
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_array_t  *mirror;
    rap_flag_t    request_body;
} rap_http_mirror_loc_conf_t;


typedef struct {
    rap_int_t     status;
} rap_http_mirror_ctx_t;


static rap_int_t rap_http_mirror_handler(rap_http_request_t *r);
static void rap_http_mirror_body_handler(rap_http_request_t *r);
static rap_int_t rap_http_mirror_handler_internal(rap_http_request_t *r);
static void *rap_http_mirror_create_loc_conf(rap_conf_t *cf);
static char *rap_http_mirror_merge_loc_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_http_mirror(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static rap_int_t rap_http_mirror_init(rap_conf_t *cf);


static rap_command_t  rap_http_mirror_commands[] = {

    { rap_string("mirror"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_mirror,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("mirror_request_body"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_mirror_loc_conf_t, request_body),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_mirror_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_mirror_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_mirror_create_loc_conf,       /* create location configuration */
    rap_http_mirror_merge_loc_conf         /* merge location configuration */
};


rap_module_t  rap_http_mirror_module = {
    RAP_MODULE_V1,
    &rap_http_mirror_module_ctx,           /* module context */
    rap_http_mirror_commands,              /* module directives */
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
rap_http_mirror_handler(rap_http_request_t *r)
{
    rap_int_t                    rc;
    rap_http_mirror_ctx_t       *ctx;
    rap_http_mirror_loc_conf_t  *mlcf;

    if (r != r->main) {
        return RAP_DECLINED;
    }

    mlcf = rap_http_get_module_loc_conf(r, rap_http_mirror_module);

    if (mlcf->mirror == NULL) {
        return RAP_DECLINED;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0, "mirror handler");

    if (mlcf->request_body) {
        ctx = rap_http_get_module_ctx(r, rap_http_mirror_module);

        if (ctx) {
            return ctx->status;
        }

        ctx = rap_pcalloc(r->pool, sizeof(rap_http_mirror_ctx_t));
        if (ctx == NULL) {
            return RAP_ERROR;
        }

        ctx->status = RAP_DONE;

        rap_http_set_ctx(r, ctx, rap_http_mirror_module);

        rc = rap_http_read_client_request_body(r, rap_http_mirror_body_handler);
        if (rc >= RAP_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        rap_http_finalize_request(r, RAP_DONE);
        return RAP_DONE;
    }

    return rap_http_mirror_handler_internal(r);
}


static void
rap_http_mirror_body_handler(rap_http_request_t *r)
{
    rap_http_mirror_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_mirror_module);

    ctx->status = rap_http_mirror_handler_internal(r);

    r->preserve_body = 1;

    r->write_event_handler = rap_http_core_run_phases;
    rap_http_core_run_phases(r);
}


static rap_int_t
rap_http_mirror_handler_internal(rap_http_request_t *r)
{
    rap_str_t                   *name;
    rap_uint_t                   i;
    rap_http_request_t          *sr;
    rap_http_mirror_loc_conf_t  *mlcf;

    mlcf = rap_http_get_module_loc_conf(r, rap_http_mirror_module);

    name = mlcf->mirror->elts;

    for (i = 0; i < mlcf->mirror->nelts; i++) {
        if (rap_http_subrequest(r, &name[i], &r->args, &sr, NULL,
                                RAP_HTTP_SUBREQUEST_BACKGROUND)
            != RAP_OK)
        {
            return RAP_HTTP_INTERNAL_SERVER_ERROR;
        }

        sr->header_only = 1;
        sr->method = r->method;
        sr->method_name = r->method_name;
    }

    return RAP_DECLINED;
}


static void *
rap_http_mirror_create_loc_conf(rap_conf_t *cf)
{
    rap_http_mirror_loc_conf_t  *mlcf;

    mlcf = rap_pcalloc(cf->pool, sizeof(rap_http_mirror_loc_conf_t));
    if (mlcf == NULL) {
        return NULL;
    }

    mlcf->mirror = RAP_CONF_UNSET_PTR;
    mlcf->request_body = RAP_CONF_UNSET;

    return mlcf;
}


static char *
rap_http_mirror_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_mirror_loc_conf_t *prev = parent;
    rap_http_mirror_loc_conf_t *conf = child;

    rap_conf_merge_ptr_value(conf->mirror, prev->mirror, NULL);
    rap_conf_merge_value(conf->request_body, prev->request_body, 1);

    return RAP_CONF_OK;
}


static char *
rap_http_mirror(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_mirror_loc_conf_t *mlcf = conf;

    rap_str_t  *value, *s;

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {
        if (mlcf->mirror != RAP_CONF_UNSET_PTR) {
            return "is duplicate";
        }

        mlcf->mirror = NULL;
        return RAP_CONF_OK;
    }

    if (mlcf->mirror == NULL) {
        return "is duplicate";
    }

    if (mlcf->mirror == RAP_CONF_UNSET_PTR) {
        mlcf->mirror = rap_array_create(cf->pool, 4, sizeof(rap_str_t));
        if (mlcf->mirror == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    s = rap_array_push(mlcf->mirror);
    if (s == NULL) {
        return RAP_CONF_ERROR;
    }

    *s = value[1];

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_mirror_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_mirror_handler;

    return RAP_OK;
}
