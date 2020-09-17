
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_str_t                 uri;
    rp_array_t              *vars;
} rp_http_auth_request_conf_t;


typedef struct {
    rp_uint_t                done;
    rp_uint_t                status;
    rp_http_request_t       *subrequest;
} rp_http_auth_request_ctx_t;


typedef struct {
    rp_int_t                 index;
    rp_http_complex_value_t  value;
    rp_http_set_variable_pt  set_handler;
} rp_http_auth_request_variable_t;


static rp_int_t rp_http_auth_request_handler(rp_http_request_t *r);
static rp_int_t rp_http_auth_request_done(rp_http_request_t *r,
    void *data, rp_int_t rc);
static rp_int_t rp_http_auth_request_set_variables(rp_http_request_t *r,
    rp_http_auth_request_conf_t *arcf, rp_http_auth_request_ctx_t *ctx);
static rp_int_t rp_http_auth_request_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static void *rp_http_auth_request_create_conf(rp_conf_t *cf);
static char *rp_http_auth_request_merge_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_auth_request_init(rp_conf_t *cf);
static char *rp_http_auth_request(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_auth_request_set(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_http_auth_request_commands[] = {

    { rp_string("auth_request"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_auth_request,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("auth_request_set"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE2,
      rp_http_auth_request_set,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_auth_request_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_auth_request_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_auth_request_create_conf,     /* create location configuration */
    rp_http_auth_request_merge_conf       /* merge location configuration */
};


rp_module_t  rp_http_auth_request_module = {
    RP_MODULE_V1,
    &rp_http_auth_request_module_ctx,     /* module context */
    rp_http_auth_request_commands,        /* module directives */
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
rp_http_auth_request_handler(rp_http_request_t *r)
{
    rp_table_elt_t               *h, *ho;
    rp_http_request_t            *sr;
    rp_http_post_subrequest_t    *ps;
    rp_http_auth_request_ctx_t   *ctx;
    rp_http_auth_request_conf_t  *arcf;

    arcf = rp_http_get_module_loc_conf(r, rp_http_auth_request_module);

    if (arcf->uri.len == 0) {
        return RP_DECLINED;
    }

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request handler");

    ctx = rp_http_get_module_ctx(r, rp_http_auth_request_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return RP_AGAIN;
        }

        /*
         * as soon as we are done - explicitly set variables to make
         * sure they will be available after internal redirects
         */

        if (rp_http_auth_request_set_variables(r, arcf, ctx) != RP_OK) {
            return RP_ERROR;
        }

        /* return appropriate status */

        if (ctx->status == RP_HTTP_FORBIDDEN) {
            return ctx->status;
        }

        if (ctx->status == RP_HTTP_UNAUTHORIZED) {
            sr = ctx->subrequest;

            h = sr->headers_out.www_authenticate;

            if (!h && sr->upstream) {
                h = sr->upstream->headers_in.www_authenticate;
            }

            if (h) {
                ho = rp_list_push(&r->headers_out.headers);
                if (ho == NULL) {
                    return RP_ERROR;
                }

                *ho = *h;

                r->headers_out.www_authenticate = ho;
            }

            return ctx->status;
        }

        if (ctx->status >= RP_HTTP_OK
            && ctx->status < RP_HTTP_SPECIAL_RESPONSE)
        {
            return RP_OK;
        }

        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "auth request unexpected status: %ui", ctx->status);

        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = rp_pcalloc(r->pool, sizeof(rp_http_auth_request_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    ps = rp_palloc(r->pool, sizeof(rp_http_post_subrequest_t));
    if (ps == NULL) {
        return RP_ERROR;
    }

    ps->handler = rp_http_auth_request_done;
    ps->data = ctx;

    if (rp_http_subrequest(r, &arcf->uri, NULL, &sr, ps,
                            RP_HTTP_SUBREQUEST_WAITED)
        != RP_OK)
    {
        return RP_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = rp_pcalloc(r->pool, sizeof(rp_http_request_body_t));
    if (sr->request_body == NULL) {
        return RP_ERROR;
    }

    sr->header_only = 1;

    ctx->subrequest = sr;

    rp_http_set_ctx(r, ctx, rp_http_auth_request_module);

    return RP_AGAIN;
}


static rp_int_t
rp_http_auth_request_done(rp_http_request_t *r, void *data, rp_int_t rc)
{
    rp_http_auth_request_ctx_t   *ctx = data;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request done s:%ui", r->headers_out.status);

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    return rc;
}


static rp_int_t
rp_http_auth_request_set_variables(rp_http_request_t *r,
    rp_http_auth_request_conf_t *arcf, rp_http_auth_request_ctx_t *ctx)
{
    rp_str_t                          val;
    rp_http_variable_t               *v;
    rp_http_variable_value_t         *vv;
    rp_http_auth_request_variable_t  *av, *last;
    rp_http_core_main_conf_t         *cmcf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request set variables");

    if (arcf->vars == NULL) {
        return RP_OK;
    }

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);
    v = cmcf->variables.elts;

    av = arcf->vars->elts;
    last = av + arcf->vars->nelts;

    while (av < last) {
        /*
         * explicitly set new value to make sure it will be available after
         * internal redirects
         */

        vv = &r->variables[av->index];

        if (rp_http_complex_value(ctx->subrequest, &av->value, &val)
            != RP_OK)
        {
            return RP_ERROR;
        }

        vv->valid = 1;
        vv->not_found = 0;
        vv->data = val.data;
        vv->len = val.len;

        if (av->set_handler) {
            /*
             * set_handler only available in cmcf->variables_keys, so we store
             * it explicitly
             */

            av->set_handler(r, vv, v[av->index].data);
        }

        av++;
    }

    return RP_OK;
}


static rp_int_t
rp_http_auth_request_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request variable");

    v->not_found = 1;

    return RP_OK;
}


static void *
rp_http_auth_request_create_conf(rp_conf_t *cf)
{
    rp_http_auth_request_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_auth_request_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    conf->vars = RP_CONF_UNSET_PTR;

    return conf;
}


static char *
rp_http_auth_request_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_auth_request_conf_t *prev = parent;
    rp_http_auth_request_conf_t *conf = child;

    rp_conf_merge_str_value(conf->uri, prev->uri, "");
    rp_conf_merge_ptr_value(conf->vars, prev->vars, NULL);

    return RP_CONF_OK;
}


static rp_int_t
rp_http_auth_request_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_auth_request_handler;

    return RP_OK;
}


static char *
rp_http_auth_request(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_auth_request_conf_t *arcf = conf;

    rp_str_t        *value;

    if (arcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "off") == 0) {
        arcf->uri.len = 0;
        arcf->uri.data = (u_char *) "";

        return RP_CONF_OK;
    }

    arcf->uri = value[1];

    return RP_CONF_OK;
}


static char *
rp_http_auth_request_set(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_auth_request_conf_t *arcf = conf;

    rp_str_t                         *value;
    rp_http_variable_t               *v;
    rp_http_auth_request_variable_t  *av;
    rp_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return RP_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (arcf->vars == RP_CONF_UNSET_PTR) {
        arcf->vars = rp_array_create(cf->pool, 1,
                                      sizeof(rp_http_auth_request_variable_t));
        if (arcf->vars == NULL) {
            return RP_CONF_ERROR;
        }
    }

    av = rp_array_push(arcf->vars);
    if (av == NULL) {
        return RP_CONF_ERROR;
    }

    v = rp_http_add_variable(cf, &value[1], RP_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return RP_CONF_ERROR;
    }

    av->index = rp_http_get_variable_index(cf, &value[1]);
    if (av->index == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = rp_http_auth_request_variable;
        v->data = (uintptr_t) av;
    }

    av->set_handler = v->set_handler;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &av->value;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
