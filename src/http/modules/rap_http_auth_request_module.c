
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_str_t                 uri;
    rap_array_t              *vars;
} rap_http_auth_request_conf_t;


typedef struct {
    rap_uint_t                done;
    rap_uint_t                status;
    rap_http_request_t       *subrequest;
} rap_http_auth_request_ctx_t;


typedef struct {
    rap_int_t                 index;
    rap_http_complex_value_t  value;
    rap_http_set_variable_pt  set_handler;
} rap_http_auth_request_variable_t;


static rap_int_t rap_http_auth_request_handler(rap_http_request_t *r);
static rap_int_t rap_http_auth_request_done(rap_http_request_t *r,
    void *data, rap_int_t rc);
static rap_int_t rap_http_auth_request_set_variables(rap_http_request_t *r,
    rap_http_auth_request_conf_t *arcf, rap_http_auth_request_ctx_t *ctx);
static rap_int_t rap_http_auth_request_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static void *rap_http_auth_request_create_conf(rap_conf_t *cf);
static char *rap_http_auth_request_merge_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_auth_request_init(rap_conf_t *cf);
static char *rap_http_auth_request(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_auth_request_set(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_http_auth_request_commands[] = {

    { rap_string("auth_request"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_auth_request,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("auth_request_set"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE2,
      rap_http_auth_request_set,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_auth_request_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_auth_request_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_auth_request_create_conf,     /* create location configuration */
    rap_http_auth_request_merge_conf       /* merge location configuration */
};


rap_module_t  rap_http_auth_request_module = {
    RAP_MODULE_V1,
    &rap_http_auth_request_module_ctx,     /* module context */
    rap_http_auth_request_commands,        /* module directives */
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
rap_http_auth_request_handler(rap_http_request_t *r)
{
    rap_table_elt_t               *h, *ho;
    rap_http_request_t            *sr;
    rap_http_post_subrequest_t    *ps;
    rap_http_auth_request_ctx_t   *ctx;
    rap_http_auth_request_conf_t  *arcf;

    arcf = rap_http_get_module_loc_conf(r, rap_http_auth_request_module);

    if (arcf->uri.len == 0) {
        return RAP_DECLINED;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request handler");

    ctx = rap_http_get_module_ctx(r, rap_http_auth_request_module);

    if (ctx != NULL) {
        if (!ctx->done) {
            return RAP_AGAIN;
        }

        /*
         * as soon as we are done - explicitly set variables to make
         * sure they will be available after internal redirects
         */

        if (rap_http_auth_request_set_variables(r, arcf, ctx) != RAP_OK) {
            return RAP_ERROR;
        }

        /* return appropriate status */

        if (ctx->status == RAP_HTTP_FORBIDDEN) {
            return ctx->status;
        }

        if (ctx->status == RAP_HTTP_UNAUTHORIZED) {
            sr = ctx->subrequest;

            h = sr->headers_out.www_authenticate;

            if (!h && sr->upstream) {
                h = sr->upstream->headers_in.www_authenticate;
            }

            if (h) {
                ho = rap_list_push(&r->headers_out.headers);
                if (ho == NULL) {
                    return RAP_ERROR;
                }

                *ho = *h;

                r->headers_out.www_authenticate = ho;
            }

            return ctx->status;
        }

        if (ctx->status >= RAP_HTTP_OK
            && ctx->status < RAP_HTTP_SPECIAL_RESPONSE)
        {
            return RAP_OK;
        }

        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "auth request unexpected status: %ui", ctx->status);

        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = rap_pcalloc(r->pool, sizeof(rap_http_auth_request_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    ps = rap_palloc(r->pool, sizeof(rap_http_post_subrequest_t));
    if (ps == NULL) {
        return RAP_ERROR;
    }

    ps->handler = rap_http_auth_request_done;
    ps->data = ctx;

    if (rap_http_subrequest(r, &arcf->uri, NULL, &sr, ps,
                            RAP_HTTP_SUBREQUEST_WAITED)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    /*
     * allocate fake request body to avoid attempts to read it and to make
     * sure real body file (if already read) won't be closed by upstream
     */

    sr->request_body = rap_pcalloc(r->pool, sizeof(rap_http_request_body_t));
    if (sr->request_body == NULL) {
        return RAP_ERROR;
    }

    sr->header_only = 1;

    ctx->subrequest = sr;

    rap_http_set_ctx(r, ctx, rap_http_auth_request_module);

    return RAP_AGAIN;
}


static rap_int_t
rap_http_auth_request_done(rap_http_request_t *r, void *data, rap_int_t rc)
{
    rap_http_auth_request_ctx_t   *ctx = data;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request done s:%ui", r->headers_out.status);

    ctx->done = 1;
    ctx->status = r->headers_out.status;

    return rc;
}


static rap_int_t
rap_http_auth_request_set_variables(rap_http_request_t *r,
    rap_http_auth_request_conf_t *arcf, rap_http_auth_request_ctx_t *ctx)
{
    rap_str_t                          val;
    rap_http_variable_t               *v;
    rap_http_variable_value_t         *vv;
    rap_http_auth_request_variable_t  *av, *last;
    rap_http_core_main_conf_t         *cmcf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request set variables");

    if (arcf->vars == NULL) {
        return RAP_OK;
    }

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);
    v = cmcf->variables.elts;

    av = arcf->vars->elts;
    last = av + arcf->vars->nelts;

    while (av < last) {
        /*
         * explicitly set new value to make sure it will be available after
         * internal redirects
         */

        vv = &r->variables[av->index];

        if (rap_http_complex_value(ctx->subrequest, &av->value, &val)
            != RAP_OK)
        {
            return RAP_ERROR;
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

    return RAP_OK;
}


static rap_int_t
rap_http_auth_request_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "auth request variable");

    v->not_found = 1;

    return RAP_OK;
}


static void *
rap_http_auth_request_create_conf(rap_conf_t *cf)
{
    rap_http_auth_request_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_auth_request_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->uri = { 0, NULL };
     */

    conf->vars = RAP_CONF_UNSET_PTR;

    return conf;
}


static char *
rap_http_auth_request_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_auth_request_conf_t *prev = parent;
    rap_http_auth_request_conf_t *conf = child;

    rap_conf_merge_str_value(conf->uri, prev->uri, "");
    rap_conf_merge_ptr_value(conf->vars, prev->vars, NULL);

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_auth_request_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_auth_request_handler;

    return RAP_OK;
}


static char *
rap_http_auth_request(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_auth_request_conf_t *arcf = conf;

    rap_str_t        *value;

    if (arcf->uri.data != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {
        arcf->uri.len = 0;
        arcf->uri.data = (u_char *) "";

        return RAP_CONF_OK;
    }

    arcf->uri = value[1];

    return RAP_CONF_OK;
}


static char *
rap_http_auth_request_set(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_auth_request_conf_t *arcf = conf;

    rap_str_t                         *value;
    rap_http_variable_t               *v;
    rap_http_auth_request_variable_t  *av;
    rap_http_compile_complex_value_t   ccv;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return RAP_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    if (arcf->vars == RAP_CONF_UNSET_PTR) {
        arcf->vars = rap_array_create(cf->pool, 1,
                                      sizeof(rap_http_auth_request_variable_t));
        if (arcf->vars == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    av = rap_array_push(arcf->vars);
    if (av == NULL) {
        return RAP_CONF_ERROR;
    }

    v = rap_http_add_variable(cf, &value[1], RAP_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return RAP_CONF_ERROR;
    }

    av->index = rap_http_get_variable_index(cf, &value[1]);
    if (av->index == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = rap_http_auth_request_variable;
        v->data = (uintptr_t) av;
    }

    av->set_handler = v->set_handler;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[2];
    ccv.complex_value = &av->value;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
