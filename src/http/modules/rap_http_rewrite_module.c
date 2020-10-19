
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_array_t  *codes;        /* uintptr_t */

    rap_uint_t    stack_size;

    rap_flag_t    log;
    rap_flag_t    uninitialized_variable_warn;
} rap_http_rewrite_loc_conf_t;


static void *rap_http_rewrite_create_loc_conf(rap_conf_t *cf);
static char *rap_http_rewrite_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_rewrite_init(rap_conf_t *cf);
static char *rap_http_rewrite(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_http_rewrite_return(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_rewrite_break(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_rewrite_if(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char * rap_http_rewrite_if_condition(rap_conf_t *cf,
    rap_http_rewrite_loc_conf_t *lcf);
static char *rap_http_rewrite_variable(rap_conf_t *cf,
    rap_http_rewrite_loc_conf_t *lcf, rap_str_t *value);
static char *rap_http_rewrite_set(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char * rap_http_rewrite_value(rap_conf_t *cf,
    rap_http_rewrite_loc_conf_t *lcf, rap_str_t *value);


static rap_command_t  rap_http_rewrite_commands[] = {

    { rap_string("rewrite"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_SIF_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                       |RAP_CONF_TAKE23,
      rap_http_rewrite,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("return"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_SIF_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                       |RAP_CONF_TAKE12,
      rap_http_rewrite_return,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("break"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_SIF_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                       |RAP_CONF_NOARGS,
      rap_http_rewrite_break,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("if"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_BLOCK|RAP_CONF_1MORE,
      rap_http_rewrite_if,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("set"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_SIF_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                       |RAP_CONF_TAKE2,
      rap_http_rewrite_set,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("rewrite_log"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_SIF_CONF|RAP_HTTP_LOC_CONF
                        |RAP_HTTP_LIF_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_rewrite_loc_conf_t, log),
      NULL },

    { rap_string("uninitialized_variable_warn"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_SIF_CONF|RAP_HTTP_LOC_CONF
                        |RAP_HTTP_LIF_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_rewrite_loc_conf_t, uninitialized_variable_warn),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_rewrite_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_rewrite_init,                 /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_rewrite_create_loc_conf,      /* create location configuration */
    rap_http_rewrite_merge_loc_conf        /* merge location configuration */
};


rap_module_t  rap_http_rewrite_module = {
    RAP_MODULE_V1,
    &rap_http_rewrite_module_ctx,          /* module context */
    rap_http_rewrite_commands,             /* module directives */
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
rap_http_rewrite_handler(rap_http_request_t *r)
{
    rap_int_t                     index;
    rap_http_script_code_pt       code;
    rap_http_script_engine_t     *e;
    rap_http_core_srv_conf_t     *cscf;
    rap_http_core_main_conf_t    *cmcf;
    rap_http_rewrite_loc_conf_t  *rlcf;

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);
    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);
    index = cmcf->phase_engine.location_rewrite_index;

    if (r->phase_handler == index && r->loc_conf == cscf->ctx->loc_conf) {
        /* skipping location rewrite phase for server null location */
        return RAP_DECLINED;
    }

    rlcf = rap_http_get_module_loc_conf(r, rap_http_rewrite_module);

    if (rlcf->codes == NULL) {
        return RAP_DECLINED;
    }

    e = rap_pcalloc(r->pool, sizeof(rap_http_script_engine_t));
    if (e == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    e->sp = rap_pcalloc(r->pool,
                        rlcf->stack_size * sizeof(rap_http_variable_value_t));
    if (e->sp == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    e->ip = rlcf->codes->elts;
    e->request = r;
    e->quote = 1;
    e->log = rlcf->log;
    e->status = RAP_DECLINED;

    while (*(uintptr_t *) e->ip) {
        code = *(rap_http_script_code_pt *) e->ip;
        code(e);
    }

    return e->status;
}


static rap_int_t
rap_http_rewrite_var(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    rap_http_variable_t          *var;
    rap_http_core_main_conf_t    *cmcf;
    rap_http_rewrite_loc_conf_t  *rlcf;

    rlcf = rap_http_get_module_loc_conf(r, rap_http_rewrite_module);

    if (rlcf->uninitialized_variable_warn == 0) {
        *v = rap_http_variable_null_value;
        return RAP_OK;
    }

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    var = cmcf->variables.elts;

    /*
     * the rap_http_rewrite_module sets variables directly in r->variables,
     * and they should be handled by rap_http_get_indexed_variable(),
     * so the handler is called only if the variable is not initialized
     */

    rap_log_error(RAP_LOG_WARN, r->connection->log, 0,
                  "using uninitialized \"%V\" variable", &var[data].name);

    *v = rap_http_variable_null_value;

    return RAP_OK;
}


static void *
rap_http_rewrite_create_loc_conf(rap_conf_t *cf)
{
    rap_http_rewrite_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_rewrite_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->stack_size = RAP_CONF_UNSET_UINT;
    conf->log = RAP_CONF_UNSET;
    conf->uninitialized_variable_warn = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_http_rewrite_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_rewrite_loc_conf_t *prev = parent;
    rap_http_rewrite_loc_conf_t *conf = child;

    uintptr_t  *code;

    rap_conf_merge_value(conf->log, prev->log, 0);
    rap_conf_merge_value(conf->uninitialized_variable_warn,
                         prev->uninitialized_variable_warn, 1);
    rap_conf_merge_uint_value(conf->stack_size, prev->stack_size, 10);

    if (conf->codes == NULL) {
        return RAP_CONF_OK;
    }

    if (conf->codes == prev->codes) {
        return RAP_CONF_OK;
    }

    code = rap_array_push_n(conf->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return RAP_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_rewrite_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_SERVER_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_rewrite_handler;

    h = rap_array_push(&cmcf->phases[RAP_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_rewrite_handler;

    return RAP_OK;
}


static char *
rap_http_rewrite(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_rewrite_loc_conf_t  *lcf = conf;

    rap_str_t                         *value;
    rap_uint_t                         last;
    rap_regex_compile_t                rc;
    rap_http_script_code_pt           *code;
    rap_http_script_compile_t          sc;
    rap_http_script_regex_code_t      *regex;
    rap_http_script_regex_end_code_t  *regex_end;
    u_char                             errstr[RAP_MAX_CONF_ERRSTR];

    regex = rap_http_script_start_code(cf->pool, &lcf->codes,
                                       sizeof(rap_http_script_regex_code_t));
    if (regex == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(regex, sizeof(rap_http_script_regex_code_t));

    value = cf->args->elts;

    if (value[2].len == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "empty replacement");
        return RAP_CONF_ERROR;
    }

    rap_memzero(&rc, sizeof(rap_regex_compile_t));

    rc.pattern = value[1];
    rc.err.len = RAP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    /* TODO: RAP_REGEX_CASELESS */

    regex->regex = rap_http_regex_compile(cf, &rc);
    if (regex->regex == NULL) {
        return RAP_CONF_ERROR;
    }

    regex->code = rap_http_script_regex_start_code;
    regex->uri = 1;
    regex->name = value[1];

    if (value[2].data[value[2].len - 1] == '?') {

        /* the last "?" drops the original arguments */
        value[2].len--;

    } else {
        regex->add_args = 1;
    }

    last = 0;

    if (rap_strncmp(value[2].data, "http://", sizeof("http://") - 1) == 0
        || rap_strncmp(value[2].data, "https://", sizeof("https://") - 1) == 0
        || rap_strncmp(value[2].data, "$scheme", sizeof("$scheme") - 1) == 0)
    {
        regex->status = RAP_HTTP_MOVED_TEMPORARILY;
        regex->redirect = 1;
        last = 1;
    }

    if (cf->args->nelts == 4) {
        if (rap_strcmp(value[3].data, "last") == 0) {
            last = 1;

        } else if (rap_strcmp(value[3].data, "break") == 0) {
            regex->break_cycle = 1;
            last = 1;

        } else if (rap_strcmp(value[3].data, "redirect") == 0) {
            regex->status = RAP_HTTP_MOVED_TEMPORARILY;
            regex->redirect = 1;
            last = 1;

        } else if (rap_strcmp(value[3].data, "permanent") == 0) {
            regex->status = RAP_HTTP_MOVED_PERMANENTLY;
            regex->redirect = 1;
            last = 1;

        } else {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return RAP_CONF_ERROR;
        }
    }

    rap_memzero(&sc, sizeof(rap_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[2];
    sc.lengths = &regex->lengths;
    sc.values = &lcf->codes;
    sc.variables = rap_http_script_variables_count(&value[2]);
    sc.main = regex;
    sc.complete_lengths = 1;
    sc.compile_args = !regex->redirect;

    if (rap_http_script_compile(&sc) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    regex = sc.main;

    regex->size = sc.size;
    regex->args = sc.args;

    if (sc.variables == 0 && !sc.dup_capture) {
        regex->lengths = NULL;
    }

    regex_end = rap_http_script_add_code(lcf->codes,
                                      sizeof(rap_http_script_regex_end_code_t),
                                      &regex);
    if (regex_end == NULL) {
        return RAP_CONF_ERROR;
    }

    regex_end->code = rap_http_script_regex_end_code;
    regex_end->uri = regex->uri;
    regex_end->args = regex->args;
    regex_end->add_args = regex->add_args;
    regex_end->redirect = regex->redirect;

    if (last) {
        code = rap_http_script_add_code(lcf->codes, sizeof(uintptr_t), &regex);
        if (code == NULL) {
            return RAP_CONF_ERROR;
        }

        *code = NULL;
    }

    regex->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
                                              - (u_char *) regex;

    return RAP_CONF_OK;
}


static char *
rap_http_rewrite_return(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_rewrite_loc_conf_t  *lcf = conf;

    u_char                            *p;
    rap_str_t                         *value, *v;
    rap_http_script_return_code_t     *ret;
    rap_http_compile_complex_value_t   ccv;

    ret = rap_http_script_start_code(cf->pool, &lcf->codes,
                                     sizeof(rap_http_script_return_code_t));
    if (ret == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    rap_memzero(ret, sizeof(rap_http_script_return_code_t));

    ret->code = rap_http_script_return_code;

    p = value[1].data;

    ret->status = rap_atoi(p, value[1].len);

    if (ret->status == (uintptr_t) RAP_ERROR) {

        if (cf->args->nelts == 2
            && (rap_strncmp(p, "http://", sizeof("http://") - 1) == 0
                || rap_strncmp(p, "https://", sizeof("https://") - 1) == 0
                || rap_strncmp(p, "$scheme", sizeof("$scheme") - 1) == 0))
        {
            ret->status = RAP_HTTP_MOVED_TEMPORARILY;
            v = &value[1];

        } else {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid return code \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

    } else {

        if (ret->status > 999) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid return code \"%V\"", &value[1]);
            return RAP_CONF_ERROR;
        }

        if (cf->args->nelts == 2) {
            return RAP_CONF_OK;
        }

        v = &value[2];
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = v;
    ccv.complex_value = &ret->text;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_rewrite_break(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_rewrite_loc_conf_t *lcf = conf;

    rap_http_script_code_pt  *code;

    code = rap_http_script_start_code(cf->pool, &lcf->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return RAP_CONF_ERROR;
    }

    *code = rap_http_script_break_code;

    return RAP_CONF_OK;
}


static char *
rap_http_rewrite_if(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_rewrite_loc_conf_t  *lcf = conf;

    void                         *mconf;
    char                         *rv;
    u_char                       *elts;
    rap_uint_t                    i;
    rap_conf_t                    save;
    rap_http_module_t            *module;
    rap_http_conf_ctx_t          *ctx, *pctx;
    rap_http_core_loc_conf_t     *clcf, *pclcf;
    rap_http_script_if_code_t    *if_code;
    rap_http_rewrite_loc_conf_t  *nlcf;

    ctx = rap_pcalloc(cf->pool, sizeof(rap_http_conf_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = rap_pcalloc(cf->pool, sizeof(void *) * rap_http_max_module);
    if (ctx->loc_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    for (i = 0; cf->cycle->modules[i]; i++) {
        if (cf->cycle->modules[i]->type != RAP_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return RAP_CONF_ERROR;
            }

            ctx->loc_conf[cf->cycle->modules[i]->ctx_index] = mconf;
        }
    }

    pclcf = pctx->loc_conf[rap_http_core_module.ctx_index];

    clcf = ctx->loc_conf[rap_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;

    if (rap_http_add_location(cf, &pclcf->locations, clcf) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (rap_http_rewrite_if_condition(cf, lcf) != RAP_CONF_OK) {
        return RAP_CONF_ERROR;
    }

    if_code = rap_array_push_n(lcf->codes, sizeof(rap_http_script_if_code_t));
    if (if_code == NULL) {
        return RAP_CONF_ERROR;
    }

    if_code->code = rap_http_script_if_code;

    elts = lcf->codes->elts;


    /* the inner directives must be compiled to the same code array */

    nlcf = ctx->loc_conf[rap_http_rewrite_module.ctx_index];
    nlcf->codes = lcf->codes;


    save = *cf;
    cf->ctx = ctx;

    if (cf->cmd_type == RAP_HTTP_SRV_CONF) {
        if_code->loc_conf = NULL;
        cf->cmd_type = RAP_HTTP_SIF_CONF;

    } else {
        if_code->loc_conf = ctx->loc_conf;
        cf->cmd_type = RAP_HTTP_LIF_CONF;
    }

    rv = rap_conf_parse(cf, NULL);

    *cf = save;

    if (rv != RAP_CONF_OK) {
        return rv;
    }


    if (elts != lcf->codes->elts) {
        if_code = (rap_http_script_if_code_t *)
                   ((u_char *) if_code + ((u_char *) lcf->codes->elts - elts));
    }

    if_code->next = (u_char *) lcf->codes->elts + lcf->codes->nelts
                                                - (u_char *) if_code;

    /* the code array belong to parent block */

    nlcf->codes = NULL;

    return RAP_CONF_OK;
}


static char *
rap_http_rewrite_if_condition(rap_conf_t *cf, rap_http_rewrite_loc_conf_t *lcf)
{
    u_char                        *p;
    size_t                         len;
    rap_str_t                     *value;
    rap_uint_t                     cur, last;
    rap_regex_compile_t            rc;
    rap_http_script_code_pt       *code;
    rap_http_script_file_code_t   *fop;
    rap_http_script_regex_code_t  *regex;
    u_char                         errstr[RAP_MAX_CONF_ERRSTR];

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (value[1].len < 1 || value[1].data[0] != '(') {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[1]);
        return RAP_CONF_ERROR;
    }

    if (value[1].len == 1) {
        cur = 2;

    } else {
        cur = 1;
        value[1].len--;
        value[1].data++;
    }

    if (value[last].len < 1 || value[last].data[value[last].len - 1] != ')') {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[last]);
        return RAP_CONF_ERROR;
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
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return RAP_CONF_ERROR;
        }

        if (rap_http_rewrite_variable(cf, lcf, &value[cur]) != RAP_CONF_OK) {
            return RAP_CONF_ERROR;
        }

        if (cur == last) {
            return RAP_CONF_OK;
        }

        cur++;

        len = value[cur].len;
        p = value[cur].data;

        if (len == 1 && p[0] == '=') {

            if (rap_http_rewrite_value(cf, lcf, &value[last]) != RAP_CONF_OK) {
                return RAP_CONF_ERROR;
            }

            code = rap_http_script_start_code(cf->pool, &lcf->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return RAP_CONF_ERROR;
            }

            *code = rap_http_script_equal_code;

            return RAP_CONF_OK;
        }

        if (len == 2 && p[0] == '!' && p[1] == '=') {

            if (rap_http_rewrite_value(cf, lcf, &value[last]) != RAP_CONF_OK) {
                return RAP_CONF_ERROR;
            }

            code = rap_http_script_start_code(cf->pool, &lcf->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return RAP_CONF_ERROR;
            }

            *code = rap_http_script_not_equal_code;
            return RAP_CONF_OK;
        }

        if ((len == 1 && p[0] == '~')
            || (len == 2 && p[0] == '~' && p[1] == '*')
            || (len == 2 && p[0] == '!' && p[1] == '~')
            || (len == 3 && p[0] == '!' && p[1] == '~' && p[2] == '*'))
        {
            regex = rap_http_script_start_code(cf->pool, &lcf->codes,
                                         sizeof(rap_http_script_regex_code_t));
            if (regex == NULL) {
                return RAP_CONF_ERROR;
            }

            rap_memzero(regex, sizeof(rap_http_script_regex_code_t));

            rap_memzero(&rc, sizeof(rap_regex_compile_t));

            rc.pattern = value[last];
            rc.options = (p[len - 1] == '*') ? RAP_REGEX_CASELESS : 0;
            rc.err.len = RAP_MAX_CONF_ERRSTR;
            rc.err.data = errstr;

            regex->regex = rap_http_regex_compile(cf, &rc);
            if (regex->regex == NULL) {
                return RAP_CONF_ERROR;
            }

            regex->code = rap_http_script_regex_start_code;
            regex->next = sizeof(rap_http_script_regex_code_t);
            regex->test = 1;
            if (p[0] == '!') {
                regex->negative_test = 1;
            }
            regex->name = value[last];

            return RAP_CONF_OK;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "unexpected \"%V\" in condition", &value[cur]);
        return RAP_CONF_ERROR;

    } else if ((len == 2 && p[0] == '-')
               || (len == 3 && p[0] == '!' && p[1] == '-'))
    {
        if (cur + 1 != last) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return RAP_CONF_ERROR;
        }

        value[last].data[value[last].len] = '\0';
        value[last].len++;

        if (rap_http_rewrite_value(cf, lcf, &value[last]) != RAP_CONF_OK) {
            return RAP_CONF_ERROR;
        }

        fop = rap_http_script_start_code(cf->pool, &lcf->codes,
                                          sizeof(rap_http_script_file_code_t));
        if (fop == NULL) {
            return RAP_CONF_ERROR;
        }

        fop->code = rap_http_script_file_code;

        if (p[1] == 'f') {
            fop->op = rap_http_script_file_plain;
            return RAP_CONF_OK;
        }

        if (p[1] == 'd') {
            fop->op = rap_http_script_file_dir;
            return RAP_CONF_OK;
        }

        if (p[1] == 'e') {
            fop->op = rap_http_script_file_exists;
            return RAP_CONF_OK;
        }

        if (p[1] == 'x') {
            fop->op = rap_http_script_file_exec;
            return RAP_CONF_OK;
        }

        if (p[0] == '!') {
            if (p[2] == 'f') {
                fop->op = rap_http_script_file_not_plain;
                return RAP_CONF_OK;
            }

            if (p[2] == 'd') {
                fop->op = rap_http_script_file_not_dir;
                return RAP_CONF_OK;
            }

            if (p[2] == 'e') {
                fop->op = rap_http_script_file_not_exists;
                return RAP_CONF_OK;
            }

            if (p[2] == 'x') {
                fop->op = rap_http_script_file_not_exec;
                return RAP_CONF_OK;
            }
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[cur]);
        return RAP_CONF_ERROR;
    }

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid condition \"%V\"", &value[cur]);

    return RAP_CONF_ERROR;
}


static char *
rap_http_rewrite_variable(rap_conf_t *cf, rap_http_rewrite_loc_conf_t *lcf,
    rap_str_t *value)
{
    rap_int_t                    index;
    rap_http_script_var_code_t  *var_code;

    value->len--;
    value->data++;

    index = rap_http_get_variable_index(cf, value);

    if (index == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    var_code = rap_http_script_start_code(cf->pool, &lcf->codes,
                                          sizeof(rap_http_script_var_code_t));
    if (var_code == NULL) {
        return RAP_CONF_ERROR;
    }

    var_code->code = rap_http_script_var_code;
    var_code->index = index;

    return RAP_CONF_OK;
}


static char *
rap_http_rewrite_set(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_rewrite_loc_conf_t  *lcf = conf;

    rap_int_t                            index;
    rap_str_t                           *value;
    rap_http_variable_t                 *v;
    rap_http_script_var_code_t          *vcode;
    rap_http_script_var_handler_code_t  *vhcode;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return RAP_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = rap_http_add_variable(cf, &value[1],
                              RAP_HTTP_VAR_CHANGEABLE|RAP_HTTP_VAR_WEAK);
    if (v == NULL) {
        return RAP_CONF_ERROR;
    }

    index = rap_http_get_variable_index(cf, &value[1]);
    if (index == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    if (v->get_handler == NULL) {
        v->get_handler = rap_http_rewrite_var;
        v->data = index;
    }

    if (rap_http_rewrite_value(cf, lcf, &value[2]) != RAP_CONF_OK) {
        return RAP_CONF_ERROR;
    }

    if (v->set_handler) {
        vhcode = rap_http_script_start_code(cf->pool, &lcf->codes,
                                   sizeof(rap_http_script_var_handler_code_t));
        if (vhcode == NULL) {
            return RAP_CONF_ERROR;
        }

        vhcode->code = rap_http_script_var_set_handler_code;
        vhcode->handler = v->set_handler;
        vhcode->data = v->data;

        return RAP_CONF_OK;
    }

    vcode = rap_http_script_start_code(cf->pool, &lcf->codes,
                                       sizeof(rap_http_script_var_code_t));
    if (vcode == NULL) {
        return RAP_CONF_ERROR;
    }

    vcode->code = rap_http_script_set_var_code;
    vcode->index = (uintptr_t) index;

    return RAP_CONF_OK;
}


static char *
rap_http_rewrite_value(rap_conf_t *cf, rap_http_rewrite_loc_conf_t *lcf,
    rap_str_t *value)
{
    rap_int_t                              n;
    rap_http_script_compile_t              sc;
    rap_http_script_value_code_t          *val;
    rap_http_script_complex_value_code_t  *complex;

    n = rap_http_script_variables_count(value);

    if (n == 0) {
        val = rap_http_script_start_code(cf->pool, &lcf->codes,
                                         sizeof(rap_http_script_value_code_t));
        if (val == NULL) {
            return RAP_CONF_ERROR;
        }

        n = rap_atoi(value->data, value->len);

        if (n == RAP_ERROR) {
            n = 0;
        }

        val->code = rap_http_script_value_code;
        val->value = (uintptr_t) n;
        val->text_len = (uintptr_t) value->len;
        val->text_data = (uintptr_t) value->data;

        return RAP_CONF_OK;
    }

    complex = rap_http_script_start_code(cf->pool, &lcf->codes,
                                 sizeof(rap_http_script_complex_value_code_t));
    if (complex == NULL) {
        return RAP_CONF_ERROR;
    }

    complex->code = rap_http_script_complex_value_code;
    complex->lengths = NULL;

    rap_memzero(&sc, sizeof(rap_http_script_compile_t));

    sc.cf = cf;
    sc.source = value;
    sc.lengths = &complex->lengths;
    sc.values = &lcf->codes;
    sc.variables = n;
    sc.complete_lengths = 1;

    if (rap_http_script_compile(&sc) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
