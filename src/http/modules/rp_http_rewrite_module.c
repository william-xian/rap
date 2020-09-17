
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_array_t  *codes;        /* uintptr_t */

    rp_uint_t    stack_size;

    rp_flag_t    log;
    rp_flag_t    uninitialized_variable_warn;
} rp_http_rewrite_loc_conf_t;


static void *rp_http_rewrite_create_loc_conf(rp_conf_t *cf);
static char *rp_http_rewrite_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_rewrite_init(rp_conf_t *cf);
static char *rp_http_rewrite(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_http_rewrite_return(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_rewrite_break(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_rewrite_if(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char * rp_http_rewrite_if_condition(rp_conf_t *cf,
    rp_http_rewrite_loc_conf_t *lcf);
static char *rp_http_rewrite_variable(rp_conf_t *cf,
    rp_http_rewrite_loc_conf_t *lcf, rp_str_t *value);
static char *rp_http_rewrite_set(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char * rp_http_rewrite_value(rp_conf_t *cf,
    rp_http_rewrite_loc_conf_t *lcf, rp_str_t *value);


static rp_command_t  rp_http_rewrite_commands[] = {

    { rp_string("rewrite"),
      RP_HTTP_SRV_CONF|RP_HTTP_SIF_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                       |RP_CONF_TAKE23,
      rp_http_rewrite,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("return"),
      RP_HTTP_SRV_CONF|RP_HTTP_SIF_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                       |RP_CONF_TAKE12,
      rp_http_rewrite_return,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("break"),
      RP_HTTP_SRV_CONF|RP_HTTP_SIF_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                       |RP_CONF_NOARGS,
      rp_http_rewrite_break,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("if"),
      RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_BLOCK|RP_CONF_1MORE,
      rp_http_rewrite_if,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("set"),
      RP_HTTP_SRV_CONF|RP_HTTP_SIF_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                       |RP_CONF_TAKE2,
      rp_http_rewrite_set,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("rewrite_log"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_SIF_CONF|RP_HTTP_LOC_CONF
                        |RP_HTTP_LIF_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_rewrite_loc_conf_t, log),
      NULL },

    { rp_string("uninitialized_variable_warn"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_SIF_CONF|RP_HTTP_LOC_CONF
                        |RP_HTTP_LIF_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_rewrite_loc_conf_t, uninitialized_variable_warn),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_rewrite_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_rewrite_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_rewrite_create_loc_conf,      /* create location configuration */
    rp_http_rewrite_merge_loc_conf        /* merge location configuration */
};


rp_module_t  rp_http_rewrite_module = {
    RP_MODULE_V1,
    &rp_http_rewrite_module_ctx,          /* module context */
    rp_http_rewrite_commands,             /* module directives */
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
rp_http_rewrite_handler(rp_http_request_t *r)
{
    rp_int_t                     index;
    rp_http_script_code_pt       code;
    rp_http_script_engine_t     *e;
    rp_http_core_srv_conf_t     *cscf;
    rp_http_core_main_conf_t    *cmcf;
    rp_http_rewrite_loc_conf_t  *rlcf;

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);
    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);
    index = cmcf->phase_engine.location_rewrite_index;

    if (r->phase_handler == index && r->loc_conf == cscf->ctx->loc_conf) {
        /* skipping location rewrite phase for server null location */
        return RP_DECLINED;
    }

    rlcf = rp_http_get_module_loc_conf(r, rp_http_rewrite_module);

    if (rlcf->codes == NULL) {
        return RP_DECLINED;
    }

    e = rp_pcalloc(r->pool, sizeof(rp_http_script_engine_t));
    if (e == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    e->sp = rp_pcalloc(r->pool,
                        rlcf->stack_size * sizeof(rp_http_variable_value_t));
    if (e->sp == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    e->ip = rlcf->codes->elts;
    e->request = r;
    e->quote = 1;
    e->log = rlcf->log;
    e->status = RP_DECLINED;

    while (*(uintptr_t *) e->ip) {
        code = *(rp_http_script_code_pt *) e->ip;
        code(e);
    }

    return e->status;
}


static rp_int_t
rp_http_rewrite_var(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    rp_http_variable_t          *var;
    rp_http_core_main_conf_t    *cmcf;
    rp_http_rewrite_loc_conf_t  *rlcf;

    rlcf = rp_http_get_module_loc_conf(r, rp_http_rewrite_module);

    if (rlcf->uninitialized_variable_warn == 0) {
        *v = rp_http_variable_null_value;
        return RP_OK;
    }

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    var = cmcf->variables.elts;

    /*
     * the rp_http_rewrite_module sets variables directly in r->variables,
     * and they should be handled by rp_http_get_indexed_variable(),
     * so the handler is called only if the variable is not initialized
     */

    rp_log_error(RP_LOG_WARN, r->connection->log, 0,
                  "using uninitialized \"%V\" variable", &var[data].name);

    *v = rp_http_variable_null_value;

    return RP_OK;
}


static void *
rp_http_rewrite_create_loc_conf(rp_conf_t *cf)
{
    rp_http_rewrite_loc_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_rewrite_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->stack_size = RP_CONF_UNSET_UINT;
    conf->log = RP_CONF_UNSET;
    conf->uninitialized_variable_warn = RP_CONF_UNSET;

    return conf;
}


static char *
rp_http_rewrite_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_rewrite_loc_conf_t *prev = parent;
    rp_http_rewrite_loc_conf_t *conf = child;

    uintptr_t  *code;

    rp_conf_merge_value(conf->log, prev->log, 0);
    rp_conf_merge_value(conf->uninitialized_variable_warn,
                         prev->uninitialized_variable_warn, 1);
    rp_conf_merge_uint_value(conf->stack_size, prev->stack_size, 10);

    if (conf->codes == NULL) {
        return RP_CONF_OK;
    }

    if (conf->codes == prev->codes) {
        return RP_CONF_OK;
    }

    code = rp_array_push_n(conf->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return RP_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;

    return RP_CONF_OK;
}


static rp_int_t
rp_http_rewrite_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_SERVER_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_rewrite_handler;

    h = rp_array_push(&cmcf->phases[RP_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_rewrite_handler;

    return RP_OK;
}


static char *
rp_http_rewrite(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_rewrite_loc_conf_t  *lcf = conf;

    rp_str_t                         *value;
    rp_uint_t                         last;
    rp_regex_compile_t                rc;
    rp_http_script_code_pt           *code;
    rp_http_script_compile_t          sc;
    rp_http_script_regex_code_t      *regex;
    rp_http_script_regex_end_code_t  *regex_end;
    u_char                             errstr[RP_MAX_CONF_ERRSTR];

    regex = rp_http_script_start_code(cf->pool, &lcf->codes,
                                       sizeof(rp_http_script_regex_code_t));
    if (regex == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(regex, sizeof(rp_http_script_regex_code_t));

    value = cf->args->elts;

    if (value[2].len == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0, "empty replacement");
        return RP_CONF_ERROR;
    }

    rp_memzero(&rc, sizeof(rp_regex_compile_t));

    rc.pattern = value[1];
    rc.err.len = RP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    /* TODO: RP_REGEX_CASELESS */

    regex->regex = rp_http_regex_compile(cf, &rc);
    if (regex->regex == NULL) {
        return RP_CONF_ERROR;
    }

    regex->code = rp_http_script_regex_start_code;
    regex->uri = 1;
    regex->name = value[1];

    if (value[2].data[value[2].len - 1] == '?') {

        /* the last "?" drops the original arguments */
        value[2].len--;

    } else {
        regex->add_args = 1;
    }

    last = 0;

    if (rp_strncmp(value[2].data, "http://", sizeof("http://") - 1) == 0
        || rp_strncmp(value[2].data, "https://", sizeof("https://") - 1) == 0
        || rp_strncmp(value[2].data, "$scheme", sizeof("$scheme") - 1) == 0)
    {
        regex->status = RP_HTTP_MOVED_TEMPORARILY;
        regex->redirect = 1;
        last = 1;
    }

    if (cf->args->nelts == 4) {
        if (rp_strcmp(value[3].data, "last") == 0) {
            last = 1;

        } else if (rp_strcmp(value[3].data, "break") == 0) {
            regex->break_cycle = 1;
            last = 1;

        } else if (rp_strcmp(value[3].data, "redirect") == 0) {
            regex->status = RP_HTTP_MOVED_TEMPORARILY;
            regex->redirect = 1;
            last = 1;

        } else if (rp_strcmp(value[3].data, "permanent") == 0) {
            regex->status = RP_HTTP_MOVED_PERMANENTLY;
            regex->redirect = 1;
            last = 1;

        } else {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return RP_CONF_ERROR;
        }
    }

    rp_memzero(&sc, sizeof(rp_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[2];
    sc.lengths = &regex->lengths;
    sc.values = &lcf->codes;
    sc.variables = rp_http_script_variables_count(&value[2]);
    sc.main = regex;
    sc.complete_lengths = 1;
    sc.compile_args = !regex->redirect;

    if (rp_http_script_compile(&sc) != RP_OK) {
        return RP_CONF_ERROR;
    }

    regex = sc.main;

    regex->size = sc.size;
    regex->args = sc.args;

    if (sc.variables == 0 && !sc.dup_capture) {
        regex->lengths = NULL;
    }

    regex_end = rp_http_script_add_code(lcf->codes,
                                      sizeof(rp_http_script_regex_end_code_t),
                                      &regex);
    if (regex_end == NULL) {
        return RP_CONF_ERROR;
    }

    regex_end->code = rp_http_script_regex_end_code;
    regex_end->uri = regex->uri;
    regex_end->args = regex->args;
    regex_end->add_args = regex->add_args;
    regex_end->redirect = regex->redirect;

    if (last) {
        code = rp_http_script_add_code(lcf->codes, sizeof(uintptr_t), &regex);
        if (code == NULL) {
            return RP_CONF_ERROR;
        }

        *code = NULL;
    }

    regex->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
                                              - (u_char *) regex;

    return RP_CONF_OK;
}


static char *
rp_http_rewrite_return(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_rewrite_loc_conf_t  *lcf = conf;

    u_char                            *p;
    rp_str_t                         *value, *v;
    rp_http_script_return_code_t     *ret;
    rp_http_compile_complex_value_t   ccv;

    ret = rp_http_script_start_code(cf->pool, &lcf->codes,
                                     sizeof(rp_http_script_return_code_t));
    if (ret == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    rp_memzero(ret, sizeof(rp_http_script_return_code_t));

    ret->code = rp_http_script_return_code;

    p = value[1].data;

    ret->status = rp_atoi(p, value[1].len);

    if (ret->status == (uintptr_t) RP_ERROR) {

        if (cf->args->nelts == 2
            && (rp_strncmp(p, "http://", sizeof("http://") - 1) == 0
                || rp_strncmp(p, "https://", sizeof("https://") - 1) == 0
                || rp_strncmp(p, "$scheme", sizeof("$scheme") - 1) == 0))
        {
            ret->status = RP_HTTP_MOVED_TEMPORARILY;
            v = &value[1];

        } else {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid return code \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

    } else {

        if (ret->status > 999) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid return code \"%V\"", &value[1]);
            return RP_CONF_ERROR;
        }

        if (cf->args->nelts == 2) {
            return RP_CONF_OK;
        }

        v = &value[2];
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = v;
    ccv.complex_value = &ret->text;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


static char *
rp_http_rewrite_break(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_rewrite_loc_conf_t *lcf = conf;

    rp_http_script_code_pt  *code;

    code = rp_http_script_start_code(cf->pool, &lcf->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return RP_CONF_ERROR;
    }

    *code = rp_http_script_break_code;

    return RP_CONF_OK;
}


static char *
rp_http_rewrite_if(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_rewrite_loc_conf_t  *lcf = conf;

    void                         *mconf;
    char                         *rv;
    u_char                       *elts;
    rp_uint_t                    i;
    rp_conf_t                    save;
    rp_http_module_t            *module;
    rp_http_conf_ctx_t          *ctx, *pctx;
    rp_http_core_loc_conf_t     *clcf, *pclcf;
    rp_http_script_if_code_t    *if_code;
    rp_http_rewrite_loc_conf_t  *nlcf;

    ctx = rp_pcalloc(cf->pool, sizeof(rp_http_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RP_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return RP_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }
    }

    pclcf = pctx->loc_conf[rp_http_core_module.ctx_index];

    clcf = ctx->loc_conf[rp_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;

    if (rp_http_add_location(cf, &pclcf->locations, clcf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (rp_http_rewrite_if_condition(cf, lcf) != RP_CONF_OK) {
        return RP_CONF_ERROR;
    }

    if_code = rp_array_push_n(lcf->codes, sizeof(rp_http_script_if_code_t));
    if (if_code == NULL) {
        return RP_CONF_ERROR;
    }

    if_code->code = rp_http_script_if_code;

    elts = lcf->codes->elts;


    /* the inner directives must be compiled to the same code array */

    nlcf = ctx->loc_conf[rp_http_rewrite_module.ctx_index];
    nlcf->codes = lcf->codes;


    save = *cf;
    cf->ctx = ctx;

    if (cf->cmd_type == RP_HTTP_SRV_CONF) {
        if_code->loc_conf = NULL;
        cf->cmd_type = RP_HTTP_SIF_CONF;

    } else {
        if_code->loc_conf = ctx->loc_conf;
        cf->cmd_type = RP_HTTP_LIF_CONF;
    }

    rv = rp_conf_parse(cf, NULL);

    *cf = save;

    if (rv != RP_CONF_OK) {
        return rv;
    }


    if (elts != lcf->codes->elts) {
        if_code = (rp_http_script_if_code_t *)
                   ((u_char *) if_code + ((u_char *) lcf->codes->elts - elts));
    }

    if_code->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
                                                - (u_char *) if_code;

    /* the code array belong to parent block */

    nlcf->codes = NULL;

    return RP_CONF_OK;
}


static char *
rp_http_rewrite_if_condition(rp_conf_t *cf, rp_http_rewrite_loc_conf_t *lcf)
{
    u_char                        *p;
    size_t                         len;
    rp_str_t                     *value;
    rp_uint_t                     cur, last;
    rp_regex_compile_t            rc;
    rp_http_script_code_pt       *code;
    rp_http_script_file_code_t   *fop;
    rp_http_script_regex_code_t  *regex;
    u_char                         errstr[RP_MAX_CONF_ERRSTR];

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (value[1].len < 1 || value[1].data[0] != '(') {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[1]);
        return RP_CONF_ERROR;
    }

    if (value[1].len == 1) {
        cur = 2;

    } else {
        cur = 1;
        value[1].len--;
        value[1].data++;
    }

    if (value[last].len < 1 || value[last].data[value[last].len - 1] != ')') {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[last]);
        return RP_CONF_ERROR;
    }

    if (value[last].len == 1) {
        last--;

    } else {
        value[last].len--;
        value[last].data[value[last].len] = '\0';
    }

    len = value[cur].len;
    p = value[cur].data;

    if (len > 1 && p[0] == '$') {

        if (cur != last && cur + 2 != last) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return RP_CONF_ERROR;
        }

        if (rp_http_rewrite_variable(cf, lcf, &value[cur]) != RP_CONF_OK) {
            return RP_CONF_ERROR;
        }

        if (cur == last) {
            return RP_CONF_OK;
        }

        cur++;

        len = value[cur].len;
        p = value[cur].data;

        if (len == 1 && p[0] == '=') {

            if (rp_http_rewrite_value(cf, lcf, &value[last]) != RP_CONF_OK) {
                return RP_CONF_ERROR;
            }

            code = rp_http_script_start_code(cf->pool, &lcf->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return RP_CONF_ERROR;
            }

            *code = rp_http_script_equal_code;

            return RP_CONF_OK;
        }

        if (len == 2 && p[0] == '!' && p[1] == '=') {

            if (rp_http_rewrite_value(cf, lcf, &value[last]) != RP_CONF_OK) {
                return RP_CONF_ERROR;
            }

            code = rp_http_script_start_code(cf->pool, &lcf->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return RP_CONF_ERROR;
            }

            *code = rp_http_script_not_equal_code;
            return RP_CONF_OK;
        }

        if ((len == 1 && p[0] == '~')
            || (len == 2 && p[0] == '~' && p[1] == '*')
            || (len == 2 && p[0] == '!' && p[1] == '~')
            || (len == 3 && p[0] == '!' && p[1] == '~' && p[2] == '*'))
        {
            regex = rp_http_script_start_code(cf->pool, &lcf->codes,
                                         sizeof(rp_http_script_regex_code_t));
            if (regex == NULL) {
                return RP_CONF_ERROR;
            }

            rp_memzero(regex, sizeof(rp_http_script_regex_code_t));

            rp_memzero(&rc, sizeof(rp_regex_compile_t));

            rc.pattern = value[last];
            rc.options = (p[len - 1] == '*') ? RP_REGEX_CASELESS : 0;
            rc.err.len = RP_MAX_CONF_ERRSTR;
            rc.err.data = errstr;

            regex->regex = rp_http_regex_compile(cf, &rc);
            if (regex->regex == NULL) {
                return RP_CONF_ERROR;
            }

            regex->code = rp_http_script_regex_start_code;
            regex->next = sizeof(rp_http_script_regex_code_t);
            regex->test = 1;
            if (p[0] == '!') {
                regex->negative_test = 1;
            }
            regex->name = value[last];

            return RP_CONF_OK;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "unexpected \"%V\" in condition", &value[cur]);
        return RP_CONF_ERROR;

    } else if ((len == 2 && p[0] == '-')
               || (len == 3 && p[0] == '!' && p[1] == '-'))
    {
        if (cur + 1 != last) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return RP_CONF_ERROR;
        }

        value[last].data[value[last].len] = '\0';
        value[last].len++;

        if (rp_http_rewrite_value(cf, lcf, &value[last]) != RP_CONF_OK) {
            return RP_CONF_ERROR;
        }

        fop = rp_http_script_start_code(cf->pool, &lcf->codes,
                                          sizeof(rp_http_script_file_code_t));
        if (fop == NULL) {
            return RP_CONF_ERROR;
        }

        fop->code = rp_http_script_file_code;

        if (p[1] == 'f') {
            fop->op = rp_http_script_file_plain;
            return RP_CONF_OK;
        }

        if (p[1] == 'd') {
            fop->op = rp_http_script_file_dir;
            return RP_CONF_OK;
        }

        if (p[1] == 'e') {
            fop->op = rp_http_script_file_exists;
            return RP_CONF_OK;
        }

        if (p[1] == 'x') {
            fop->op = rp_http_script_file_exec;
            return RP_CONF_OK;
        }

        if (p[0] == '!') {
            if (p[2] == 'f') {
                fop->op = rp_http_script_file_not_plain;
                return RP_CONF_OK;
            }

            if (p[2] == 'd') {
                fop->op = rp_http_script_file_not_dir;
                return RP_CONF_OK;
            }

            if (p[2] == 'e') {
                fop->op = rp_http_script_file_not_exists;
                return RP_CONF_OK;
            }

            if (p[2] == 'x') {
                fop->op = rp_http_script_file_not_exec;
                return RP_CONF_OK;
            }
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[cur]);
        return RP_CONF_ERROR;
    }

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid condition \"%V\"", &value[cur]);

    return RP_CONF_ERROR;
}


static char *
rp_http_rewrite_variable(rp_conf_t *cf, rp_http_rewrite_loc_conf_t *lcf,
    rp_str_t *value)
{
    rp_int_t                    index;
    rp_http_script_var_code_t  *var_code;

    value->len--;
    value->data++;

    index = rp_http_get_variable_index(cf, value);

    if (index == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    var_code = rp_http_script_start_code(cf->pool, &lcf->codes,
                                          sizeof(rp_http_script_var_code_t));
    if (var_code == NULL) {
        return RP_CONF_ERROR;
    }

    var_code->code = rp_http_script_var_code;
    var_code->index = index;

    return RP_CONF_OK;
}


static char *
rp_http_rewrite_set(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_rewrite_loc_conf_t  *lcf = conf;

    rp_int_t                            index;
    rp_str_t                           *value;
    rp_http_variable_t                 *v;
    rp_http_script_var_code_t          *vcode;
    rp_http_script_var_handler_code_t  *vhcode;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return RP_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = rp_http_add_variable(cf, &value[1],
                              RP_HTTP_VAR_CHANGEABLE|RP_HTTP_VAR_WEAK);
    if (v == NULL) {
        return RP_CONF_ERROR;
    }

    index = rp_http_get_variable_index(cf, &value[1]);
    if (index == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = rp_http_rewrite_var;
        v->data = index;
    }

    if (rp_http_rewrite_value(cf, lcf, &value[2]) != RP_CONF_OK) {
        return RP_CONF_ERROR;
    }

    if (v->set_handler) {
        vhcode = rp_http_script_start_code(cf->pool, &lcf->codes,
                                   sizeof(rp_http_script_var_handler_code_t));
        if (vhcode == NULL) {
            return RP_CONF_ERROR;
        }

        vhcode->code = rp_http_script_var_set_handler_code;
        vhcode->handler = v->set_handler;
        vhcode->data = v->data;

        return RP_CONF_OK;
    }

    vcode = rp_http_script_start_code(cf->pool, &lcf->codes,
                                       sizeof(rp_http_script_var_code_t));
    if (vcode == NULL) {
        return RP_CONF_ERROR;
    }

    vcode->code = rp_http_script_set_var_code;
    vcode->index = (uintptr_t) index;

    return RP_CONF_OK;
}


static char *
rp_http_rewrite_value(rp_conf_t *cf, rp_http_rewrite_loc_conf_t *lcf,
    rp_str_t *value)
{
    rp_int_t                              n;
    rp_http_script_compile_t              sc;
    rp_http_script_value_code_t          *val;
    rp_http_script_complex_value_code_t  *complex;

    n = rp_http_script_variables_count(value);

    if (n == 0) {
        val = rp_http_script_start_code(cf->pool, &lcf->codes,
                                         sizeof(rp_http_script_value_code_t));
        if (val == NULL) {
            return RP_CONF_ERROR;
        }

        n = rp_atoi(value->data, value->len);

        if (n == RP_ERROR) {
            n = 0;
        }

        val->code = rp_http_script_value_code;
        val->value = (uintptr_t) n;
        val->text_len = (uintptr_t) value->len;
        val->text_data = (uintptr_t) value->data;

        return RP_CONF_OK;
    }

    complex = rp_http_script_start_code(cf->pool, &lcf->codes,
                                 sizeof(rp_http_script_complex_value_code_t));
    if (complex == NULL) {
        return RP_CONF_ERROR;
    }

    complex->code = rp_http_script_complex_value_code;
    complex->lengths = NULL;

    rp_memzero(&sc, sizeof(rp_http_script_compile_t));

    sc.cf = cf;
    sc.source = value;
    sc.lengths = &complex->lengths;
    sc.values = &lcf->codes;
    sc.variables = n;
    sc.complete_lengths = 1;

    if (rp_http_script_compile(&sc) != RP_OK) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
