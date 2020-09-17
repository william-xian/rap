
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_array_t  *mirror;
    rp_flag_t    request_body;
} rp_http_mirror_loc_conf_t;


typedef struct {
    rp_int_t     status;
} rp_http_mirror_ctx_t;


static rp_int_t rp_http_mirror_handler(rp_http_request_t *r);
static void rp_http_mirror_body_handler(rp_http_request_t *r);
static rp_int_t rp_http_mirror_handler_internal(rp_http_request_t *r);
static void *rp_http_mirror_create_loc_conf(rp_conf_t *cf);
static char *rp_http_mirror_merge_loc_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_http_mirror(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static rp_int_t rp_http_mirror_init(rp_conf_t *cf);


static rp_command_t  rp_http_mirror_commands[] = {

    { rp_string("mirror"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_mirror,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("mirror_request_body"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_mirror_loc_conf_t, request_body),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_mirror_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_mirror_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_mirror_create_loc_conf,       /* create location configuration */
    rp_http_mirror_merge_loc_conf         /* merge location configuration */
};


rp_module_t  rp_http_mirror_module = {
    RP_MODULE_V1,
    &rp_http_mirror_module_ctx,           /* module context */
    rp_http_mirror_commands,              /* module directives */
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
rp_http_mirror_handler(rp_http_request_t *r)
{
    rp_int_t                    rc;
    rp_http_mirror_ctx_t       *ctx;
    rp_http_mirror_loc_conf_t  *mlcf;

    if (r != r->main) {
        return RP_DECLINED;
    }

    mlcf = rp_http_get_module_loc_conf(r, rp_http_mirror_module);

    if (mlcf->mirror == NULL) {
        return RP_DECLINED;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0, "mirror handler");

    if (mlcf->request_body) {
        ctx = rp_http_get_module_ctx(r, rp_http_mirror_module);

        if (ctx) {
            return ctx->status;
        }

        ctx = rp_pcalloc(r->pool, sizeof(rp_http_mirror_ctx_t));
        if (ctx == NULL) {
            return RP_ERROR;
        }

        ctx->status = RP_DONE;

        rp_http_set_ctx(r, ctx, rp_http_mirror_module);

        rc = rp_http_read_client_request_body(r, rp_http_mirror_body_handler);
        if (rc >= RP_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }

        rp_http_finalize_request(r, RP_DONE);
        return RP_DONE;
    }

    return rp_http_mirror_handler_internal(r);
}


static void
rp_http_mirror_body_handler(rp_http_request_t *r)
{
    rp_http_mirror_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_mirror_module);

    ctx->status = rp_http_mirror_handler_internal(r);

    r->preserve_body = 1;

    r->write_event_handler = rp_http_core_run_phases;
    rp_http_core_run_phases(r);
}


static rp_int_t
rp_http_mirror_handler_internal(rp_http_request_t *r)
{
    rp_str_t                   *name;
    rp_uint_t                   i;
    rp_http_request_t          *sr;
    rp_http_mirror_loc_conf_t  *mlcf;

    mlcf = rp_http_get_module_loc_conf(r, rp_http_mirror_module);

    name = mlcf->mirror->elts;

    for (i = 0; i < mlcf->mirror->nelts; i++) {
        if (rp_http_subrequest(r, &name[i], &r->args, &sr, NULL,
                                RP_HTTP_SUBREQUEST_BACKGROUND)
            != RP_OK)
        {
            return RP_HTTP_INTERNAL_SERVER_ERROR;
        }

        sr->header_only = 1;
        sr->method = r->method;
        sr->method_name = r->method_name;
    }

    return RP_DECLINED;
}


static void *
rp_http_mirror_create_loc_conf(rp_conf_t *cf)
{
    rp_http_mirror_loc_conf_t  *mlcf;

    mlcf = rp_pcalloc(cf->pool, sizeof(rp_http_mirror_loc_conf_t));
    if (mlcf == NULL) {
        return NULL;
    }

    mlcf->mirror = RP_CONF_UNSET_PTR;
    mlcf->request_body = RP_CONF_UNSET;

    return mlcf;
}


static char *
rp_http_mirror_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_mirror_loc_conf_t *prev = parent;
    rp_http_mirror_loc_conf_t *conf = child;

    rp_conf_merge_ptr_value(conf->mirror, prev->mirror, NULL);
    rp_conf_merge_value(conf->request_body, prev->request_body, 1);

    return RP_CONF_OK;
}


static char *
rp_http_mirror(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_mirror_loc_conf_t *mlcf = conf;

    rp_str_t  *value, *s;

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "off") == 0) {
        if (mlcf->mirror != RP_CONF_UNSET_PTR) {
            return "is duplicate";
        }

        mlcf->mirror = NULL;
        return RP_CONF_OK;
    }

    if (mlcf->mirror == NULL) {
        return "is duplicate";
    }

    if (mlcf->mirror == RP_CONF_UNSET_PTR) {
        mlcf->mirror = rp_array_create(cf->pool, 4, sizeof(rp_str_t));
        if (mlcf->mirror == NULL) {
            return RP_CONF_ERROR;
        }
    }

    s = rp_array_push(mlcf->mirror);
    if (s == NULL) {
        return RP_CONF_ERROR;
    }

    *s = value[1];

    return RP_CONF_OK;
}


static rp_int_t
rp_http_mirror_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_PRECONTENT_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_mirror_handler;

    return RP_OK;
}
