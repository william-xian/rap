
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap_http_perl_module.h>


typedef struct {
    PerlInterpreter   *perl;
    HV                *rap;
    rap_array_t       *modules;
    rap_array_t       *requires;
} rap_http_perl_main_conf_t;


typedef struct {
    SV                *sub;
    rap_str_t          handler;
} rap_http_perl_loc_conf_t;


typedef struct {
    SV                *sub;
    rap_str_t          handler;
} rap_http_perl_variable_t;


#if (RAP_HTTP_SSI)
static rap_int_t rap_http_perl_ssi(rap_http_request_t *r,
    rap_http_ssi_ctx_t *ssi_ctx, rap_str_t **params);
#endif

static char *rap_http_perl_init_interpreter(rap_conf_t *cf,
    rap_http_perl_main_conf_t *pmcf);
static PerlInterpreter *rap_http_perl_create_interpreter(rap_conf_t *cf,
    rap_http_perl_main_conf_t *pmcf);
static rap_int_t rap_http_perl_run_requires(pTHX_ rap_array_t *requires,
    rap_log_t *log);
static rap_int_t rap_http_perl_call_handler(pTHX_ rap_http_request_t *r,
    rap_http_perl_ctx_t *ctx, HV *rap, SV *sub, SV **args,
    rap_str_t *handler, rap_str_t *rv);
static void rap_http_perl_eval_anon_sub(pTHX_ rap_str_t *handler, SV **sv);

static rap_int_t rap_http_perl_preconfiguration(rap_conf_t *cf);
static void *rap_http_perl_create_main_conf(rap_conf_t *cf);
static char *rap_http_perl_init_main_conf(rap_conf_t *cf, void *conf);
static void *rap_http_perl_create_loc_conf(rap_conf_t *cf);
static char *rap_http_perl_merge_loc_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_http_perl(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_http_perl_set(rap_conf_t *cf, rap_command_t *cmd, void *conf);

#if (RAP_HAVE_PERL_MULTIPLICITY)
static void rap_http_perl_cleanup_perl(void *data);
#endif

static rap_int_t rap_http_perl_init_worker(rap_cycle_t *cycle);
static void rap_http_perl_exit(rap_cycle_t *cycle);


static rap_command_t  rap_http_perl_commands[] = {

    { rap_string("perl_modules"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_perl_main_conf_t, modules),
      NULL },

    { rap_string("perl_require"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_array_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_perl_main_conf_t, requires),
      NULL },

    { rap_string("perl"),
      RAP_HTTP_LOC_CONF|RAP_HTTP_LMT_CONF|RAP_CONF_TAKE1,
      rap_http_perl,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("perl_set"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE2,
      rap_http_perl_set,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_perl_module_ctx = {
    rap_http_perl_preconfiguration,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_http_perl_create_main_conf,        /* create main configuration */
    rap_http_perl_init_main_conf,          /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_perl_create_loc_conf,         /* create location configuration */
    rap_http_perl_merge_loc_conf           /* merge location configuration */
};


rap_module_t  rap_http_perl_module = {
    RAP_MODULE_V1,
    &rap_http_perl_module_ctx,             /* module context */
    rap_http_perl_commands,                /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    rap_http_perl_init_worker,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    rap_http_perl_exit,                    /* exit master */
    RAP_MODULE_V1_PADDING
};


#if (RAP_HTTP_SSI)

#define RAP_HTTP_PERL_SSI_SUB  0
#define RAP_HTTP_PERL_SSI_ARG  1


static rap_http_ssi_param_t  rap_http_perl_ssi_params[] = {
    { rap_string("sub"), RAP_HTTP_PERL_SSI_SUB, 1, 0 },
    { rap_string("arg"), RAP_HTTP_PERL_SSI_ARG, 0, 1 },
    { rap_null_string, 0, 0, 0 }
};

static rap_http_ssi_command_t  rap_http_perl_ssi_command = {
    rap_string("perl"), rap_http_perl_ssi, rap_http_perl_ssi_params, 0, 0, 1
};

#endif


static rap_str_t         rap_null_name = rap_null_string;
static HV               *rap_stash;

#if (RAP_HAVE_PERL_MULTIPLICITY)
static rap_uint_t        rap_perl_term;
#else
static PerlInterpreter  *perl;
#endif


static void
rap_http_perl_xs_init(pTHX)
{
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);

    rap_stash = gv_stashpv("rap", TRUE);
}


static rap_int_t
rap_http_perl_handler(rap_http_request_t *r)
{
    r->main->count++;

    rap_http_perl_handle_request(r);

    return RAP_DONE;
}


void
rap_http_perl_handle_request(rap_http_request_t *r)
{
    SV                         *sub;
    rap_int_t                   rc;
    rap_str_t                   uri, args, *handler;
    rap_uint_t                  flags;
    rap_http_perl_ctx_t        *ctx;
    rap_http_perl_loc_conf_t   *plcf;
    rap_http_perl_main_conf_t  *pmcf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0, "perl handler");

    ctx = rap_http_get_module_ctx(r, rap_http_perl_module);

    if (ctx == NULL) {
        ctx = rap_pcalloc(r->pool, sizeof(rap_http_perl_ctx_t));
        if (ctx == NULL) {
            rap_http_finalize_request(r, RAP_ERROR);
            return;
        }

        rap_http_set_ctx(r, ctx, rap_http_perl_module);

        ctx->request = r;
    }

    pmcf = rap_http_get_module_main_conf(r, rap_http_perl_module);

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    if (ctx->next == NULL) {
        plcf = rap_http_get_module_loc_conf(r, rap_http_perl_module);
        sub = plcf->sub;
        handler = &plcf->handler;

    } else {
        sub = ctx->next;
        handler = &rap_null_name;
        ctx->next = NULL;
    }

    rc = rap_http_perl_call_handler(aTHX_ r, ctx, pmcf->rap, sub, NULL,
                                    handler, NULL);

    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl handler done: %i", rc);

    if (rc > 600) {
        rc = RAP_OK;
    }

    if (ctx->redirect_uri.len) {
        uri = ctx->redirect_uri;

    } else {
        uri.len = 0;
    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    if (rc == RAP_ERROR) {
        rap_http_finalize_request(r, rc);
        return;
    }

    if (ctx->done || ctx->next) {
        rap_http_finalize_request(r, RAP_DONE);
        return;
    }

    if (uri.len) {
        if (uri.data[0] == '@') {
            rap_http_named_location(r, &uri);

        } else {
            rap_str_null(&args);
            flags = RAP_HTTP_LOG_UNSAFE;

            if (rap_http_parse_unsafe_uri(r, &uri, &args, &flags) != RAP_OK) {
                rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            rap_http_internal_redirect(r, &uri, &args);
        }

        rap_http_finalize_request(r, RAP_DONE);
        return;
    }

    if (rc == RAP_OK || rc == RAP_HTTP_OK) {
        rap_http_send_special(r, RAP_HTTP_LAST);
        ctx->done = 1;
    }

    rap_http_finalize_request(r, rc);
}


void
rap_http_perl_sleep_handler(rap_http_request_t *r)
{
    rap_event_t  *wev;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sleep handler");

    wev = r->connection->write;

    if (wev->delayed) {

        if (rap_handle_write_event(wev, 0) != RAP_OK) {
            rap_http_finalize_request(r, RAP_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    rap_http_perl_handle_request(r);
}


static rap_int_t
rap_http_perl_variable(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    rap_http_perl_variable_t *pv = (rap_http_perl_variable_t *) data;

    rap_int_t                   rc;
    rap_str_t                   value;
    rap_uint_t                  saved;
    rap_http_perl_ctx_t        *ctx;
    rap_http_perl_main_conf_t  *pmcf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable handler");

    ctx = rap_http_get_module_ctx(r, rap_http_perl_module);

    if (ctx == NULL) {
        ctx = rap_pcalloc(r->pool, sizeof(rap_http_perl_ctx_t));
        if (ctx == NULL) {
            return RAP_ERROR;
        }

        rap_http_set_ctx(r, ctx, rap_http_perl_module);

        ctx->request = r;
    }

    saved = ctx->variable;
    ctx->variable = 1;

    pmcf = rap_http_get_module_main_conf(r, rap_http_perl_module);

    value.data = NULL;

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    rc = rap_http_perl_call_handler(aTHX_ r, ctx, pmcf->rap, pv->sub, NULL,
                                    &pv->handler, &value);

    }

    if (value.data) {
        v->len = value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = value.data;

    } else {
        v->not_found = 1;
    }

    ctx->variable = saved;
    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable done");

    return rc;
}


#if (RAP_HTTP_SSI)

static rap_int_t
rap_http_perl_ssi(rap_http_request_t *r, rap_http_ssi_ctx_t *ssi_ctx,
    rap_str_t **params)
{
    SV                         *sv, **asv;
    rap_int_t                   rc;
    rap_str_t                  *handler, **args;
    rap_uint_t                  i;
    rap_http_perl_ctx_t        *ctx;
    rap_http_perl_main_conf_t  *pmcf;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl ssi handler");

    ctx = rap_http_get_module_ctx(r, rap_http_perl_module);

    if (ctx == NULL) {
        ctx = rap_pcalloc(r->pool, sizeof(rap_http_perl_ctx_t));
        if (ctx == NULL) {
            return RAP_ERROR;
        }

        rap_http_set_ctx(r, ctx, rap_http_perl_module);

        ctx->request = r;
    }

    pmcf = rap_http_get_module_main_conf(r, rap_http_perl_module);

    ctx->ssi = ssi_ctx;
    ctx->header_sent = 1;

    handler = params[RAP_HTTP_PERL_SSI_SUB];
    handler->data[handler->len] = '\0';

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

#if 0

    /* the code is disabled to force the precompiled perl code using only */

    rap_http_perl_eval_anon_sub(aTHX_ handler, &sv);

    if (sv == &PL_sv_undef) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "eval_pv(\"%V\") failed", handler);
        return RAP_ERROR;
    }

    if (sv == NULL) {
        sv = newSVpvn((char *) handler->data, handler->len);
    }

#endif

    sv = newSVpvn((char *) handler->data, handler->len);

    args = &params[RAP_HTTP_PERL_SSI_ARG];

    if (args[0]) {

        for (i = 0; args[i]; i++) { /* void */ }

        asv = rap_pcalloc(r->pool, (i + 1) * sizeof(SV *));

        if (asv == NULL) {
            SvREFCNT_dec(sv);
            return RAP_ERROR;
        }

        asv[0] = (SV *) (uintptr_t) i;

        for (i = 0; args[i]; i++) {
            asv[i + 1] = newSVpvn((char *) args[i]->data, args[i]->len);
        }

    } else {
        asv = NULL;
    }

    rc = rap_http_perl_call_handler(aTHX_ r, ctx, pmcf->rap, sv, asv,
                                    handler, NULL);

    SvREFCNT_dec(sv);

    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;
    ctx->ssi = NULL;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0, "perl ssi done");

    return rc;
}

#endif


static char *
rap_http_perl_init_interpreter(rap_conf_t *cf, rap_http_perl_main_conf_t *pmcf)
{
    rap_str_t           *m;
    rap_uint_t           i;
#if (RAP_HAVE_PERL_MULTIPLICITY)
    rap_pool_cleanup_t  *cln;

    cln = rap_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RAP_CONF_ERROR;
    }

#endif

#ifdef RAP_PERL_MODULES
    if (pmcf->modules == RAP_CONF_UNSET_PTR) {

        pmcf->modules = rap_array_create(cf->pool, 1, sizeof(rap_str_t));
        if (pmcf->modules == NULL) {
            return RAP_CONF_ERROR;
        }

        m = rap_array_push(pmcf->modules);
        if (m == NULL) {
            return RAP_CONF_ERROR;
        }

        rap_str_set(m, RAP_PERL_MODULES);
    }
#endif

    if (pmcf->modules != RAP_CONF_UNSET_PTR) {
        m = pmcf->modules->elts;
        for (i = 0; i < pmcf->modules->nelts; i++) {
            if (rap_conf_full_name(cf->cycle, &m[i], 0) != RAP_OK) {
                return RAP_CONF_ERROR;
            }
        }
    }

#if !(RAP_HAVE_PERL_MULTIPLICITY)

    if (perl) {

        if (rap_set_environment(cf->cycle, NULL) == NULL) {
            return RAP_CONF_ERROR;
        }

        if (rap_http_perl_run_requires(aTHX_ pmcf->requires, cf->log)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }

        pmcf->perl = perl;
        pmcf->rap = rap_stash;

        return RAP_CONF_OK;
    }

#endif

    if (rap_stash == NULL) {
        PERL_SYS_INIT(&rap_argc, &rap_argv);
    }

    pmcf->perl = rap_http_perl_create_interpreter(cf, pmcf);

    if (pmcf->perl == NULL) {
        return RAP_CONF_ERROR;
    }

    pmcf->rap = rap_stash;

#if (RAP_HAVE_PERL_MULTIPLICITY)

    cln->handler = rap_http_perl_cleanup_perl;
    cln->data = pmcf->perl;

#else

    perl = pmcf->perl;

#endif

    return RAP_CONF_OK;
}


static PerlInterpreter *
rap_http_perl_create_interpreter(rap_conf_t *cf,
    rap_http_perl_main_conf_t *pmcf)
{
    int                n;
    STRLEN             len;
    SV                *sv;
    char              *ver, **embedding;
    rap_str_t         *m;
    rap_uint_t         i;
    PerlInterpreter   *perl;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, cf->log, 0, "create perl interpreter");

    if (rap_set_environment(cf->cycle, NULL) == NULL) {
        return NULL;
    }

    perl = perl_alloc();
    if (perl == NULL) {
        rap_log_error(RAP_LOG_ALERT, cf->log, 0, "perl_alloc() failed");
        return NULL;
    }

    {

    dTHXa(perl);
    PERL_SET_CONTEXT(perl);
    PERL_SET_INTERP(perl);

    perl_construct(perl);

#ifdef PERL_EXIT_DESTRUCT_END
    PL_exit_flags |= PERL_EXIT_DESTRUCT_END;
#endif

    n = (pmcf->modules != RAP_CONF_UNSET_PTR) ? pmcf->modules->nelts * 2 : 0;

    embedding = rap_palloc(cf->pool, (5 + n) * sizeof(char *));
    if (embedding == NULL) {
        goto fail;
    }

    embedding[0] = "";

    if (n++) {
        m = pmcf->modules->elts;
        for (i = 0; i < pmcf->modules->nelts; i++) {
            embedding[2 * i + 1] = "-I";
            embedding[2 * i + 2] = (char *) m[i].data;
        }
    }

    embedding[n++] = "-Mrap";
    embedding[n++] = "-e";
    embedding[n++] = "0";
    embedding[n] = NULL;

    n = perl_parse(perl, rap_http_perl_xs_init, n, embedding, NULL);

    if (n != 0) {
        rap_log_error(RAP_LOG_ALERT, cf->log, 0, "perl_parse() failed: %d", n);
        goto fail;
    }

    sv = get_sv("rap::VERSION", FALSE);
    ver = SvPV(sv, len);

    if (rap_strcmp(ver, RAP_VERSION) != 0) {
        rap_log_error(RAP_LOG_ALERT, cf->log, 0,
                      "version " RAP_VERSION " of rap.pm is required, "
                      "but %s was found", ver);
        goto fail;
    }

    if (rap_http_perl_run_requires(aTHX_ pmcf->requires, cf->log) != RAP_OK) {
        goto fail;
    }

    }

    return perl;

fail:

    (void) perl_destruct(perl);

    perl_free(perl);

    return NULL;
}


static rap_int_t
rap_http_perl_run_requires(pTHX_ rap_array_t *requires, rap_log_t *log)
{
    u_char      *err;
    STRLEN       len;
    rap_str_t   *script;
    rap_uint_t   i;

    if (requires == RAP_CONF_UNSET_PTR) {
        return RAP_OK;
    }

    script = requires->elts;
    for (i = 0; i < requires->nelts; i++) {

        require_pv((char *) script[i].data);

        if (SvTRUE(ERRSV)) {

            err = (u_char *) SvPV(ERRSV, len);
            while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

            rap_log_error(RAP_LOG_EMERG, log, 0,
                          "require_pv(\"%s\") failed: \"%*s\"",
                          script[i].data, len + 1, err);

            return RAP_ERROR;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_perl_call_handler(pTHX_ rap_http_request_t *r,
    rap_http_perl_ctx_t *ctx, HV *rap, SV *sub, SV **args,
    rap_str_t *handler, rap_str_t *rv)
{
    SV                *sv;
    int                n, status;
    char              *line;
    u_char            *err;
    STRLEN             len, n_a;
    rap_uint_t         i;
    rap_connection_t  *c;

    dSP;

    status = 0;

    ctx->error = 0;
    ctx->status = RAP_OK;

    ENTER;
    SAVETMPS;

    PUSHMARK(sp);

    sv = sv_2mortal(sv_bless(newRV_noinc(newSViv(PTR2IV(ctx))), rap));
    XPUSHs(sv);

    if (args) {
        EXTEND(sp, (intptr_t) args[0]);

        for (i = 1; i <= (uintptr_t) args[0]; i++) {
            PUSHs(sv_2mortal(args[i]));
        }
    }

    PUTBACK;

    c = r->connection;

    n = call_sv(sub, G_EVAL);

    SPAGAIN;

    if (n) {
        if (rv == NULL) {
            status = POPi;

            rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                           "call_sv: %d", status);

        } else {
            line = SvPVx(POPs, n_a);
            rv->len = n_a;

            rv->data = rap_pnalloc(r->pool, n_a);
            if (rv->data == NULL) {
                return RAP_ERROR;
            }

            rap_memcpy(rv->data, line, n_a);
        }
    }

    PUTBACK;

    FREETMPS;
    LEAVE;

    if (ctx->error) {

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "call_sv: error, %d", ctx->status);

        if (ctx->status != RAP_OK) {
            return ctx->status;
        }

        return RAP_ERROR;
    }

    /* check $@ */

    if (SvTRUE(ERRSV)) {

        err = (u_char *) SvPV(ERRSV, len);
        while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

        rap_log_error(RAP_LOG_ERR, c->log, 0,
                      "call_sv(\"%V\") failed: \"%*s\"", handler, len + 1, err);

        if (rv) {
            return RAP_ERROR;
        }

        ctx->redirect_uri.len = 0;

        if (ctx->header_sent) {
            return RAP_ERROR;
        }

        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (n != 1) {
        rap_log_error(RAP_LOG_ALERT, c->log, 0,
                      "call_sv(\"%V\") returned %d results", handler, n);
        status = RAP_OK;
    }

    if (rv) {
        return RAP_OK;
    }

    return (rap_int_t) status;
}


static void
rap_http_perl_eval_anon_sub(pTHX_ rap_str_t *handler, SV **sv)
{
    u_char  *p;

    for (p = handler->data; *p; p++) {
        if (*p != ' ' && *p != '\t' && *p != CR && *p != LF) {
            break;
        }
    }

    if (rap_strncmp(p, "sub ", 4) == 0
        || rap_strncmp(p, "sub{", 4) == 0
        || rap_strncmp(p, "use ", 4) == 0)
    {
        *sv = eval_pv((char *) p, FALSE);

        /* eval_pv() does not set ERRSV on failure */

        return;
    }

    *sv = NULL;
}


static void *
rap_http_perl_create_main_conf(rap_conf_t *cf)
{
    rap_http_perl_main_conf_t  *pmcf;

    pmcf = rap_pcalloc(cf->pool, sizeof(rap_http_perl_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    pmcf->modules = RAP_CONF_UNSET_PTR;
    pmcf->requires = RAP_CONF_UNSET_PTR;

    return pmcf;
}


static char *
rap_http_perl_init_main_conf(rap_conf_t *cf, void *conf)
{
    rap_http_perl_main_conf_t *pmcf = conf;

    if (pmcf->perl == NULL) {
        if (rap_http_perl_init_interpreter(cf, pmcf) != RAP_CONF_OK) {
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}


#if (RAP_HAVE_PERL_MULTIPLICITY)

static void
rap_http_perl_cleanup_perl(void *data)
{
    PerlInterpreter  *perl = data;

    PERL_SET_CONTEXT(perl);
    PERL_SET_INTERP(perl);

    (void) perl_destruct(perl);

    perl_free(perl);

    if (rap_perl_term) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, rap_cycle->log, 0, "perl term");

        PERL_SYS_TERM();
    }
}

#endif


static rap_int_t
rap_http_perl_preconfiguration(rap_conf_t *cf)
{
#if (RAP_HTTP_SSI)
    rap_int_t                  rc;
    rap_http_ssi_main_conf_t  *smcf;

    smcf = rap_http_conf_get_module_main_conf(cf, rap_http_ssi_filter_module);

    rc = rap_hash_add_key(&smcf->commands, &rap_http_perl_ssi_command.name,
                          &rap_http_perl_ssi_command, RAP_HASH_READONLY_KEY);

    if (rc != RAP_OK) {
        if (rc == RAP_BUSY) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "conflicting SSI command \"%V\"",
                               &rap_http_perl_ssi_command.name);
        }

        return RAP_ERROR;
    }
#endif

    return RAP_OK;
}


static void *
rap_http_perl_create_loc_conf(rap_conf_t *cf)
{
    rap_http_perl_loc_conf_t *plcf;

    plcf = rap_pcalloc(cf->pool, sizeof(rap_http_perl_loc_conf_t));
    if (plcf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     plcf->handler = { 0, NULL };
     */

    return plcf;
}


static char *
rap_http_perl_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_perl_loc_conf_t *prev = parent;
    rap_http_perl_loc_conf_t *conf = child;

    if (conf->sub == NULL) {
        conf->sub = prev->sub;
        conf->handler = prev->handler;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_perl(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_perl_loc_conf_t *plcf = conf;

    rap_str_t                  *value;
    rap_http_core_loc_conf_t   *clcf;
    rap_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (plcf->handler.data) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "duplicate perl handler \"%V\"", &value[1]);
        return RAP_CONF_ERROR;
    }

    pmcf = rap_http_conf_get_module_main_conf(cf, rap_http_perl_module);

    if (pmcf->perl == NULL) {
        if (rap_http_perl_init_interpreter(cf, pmcf) != RAP_CONF_OK) {
            return RAP_CONF_ERROR;
        }
    }

    plcf->handler = value[1];

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    rap_http_perl_eval_anon_sub(aTHX_ &value[1], &plcf->sub);

    if (plcf->sub == &PL_sv_undef) {
        rap_conf_log_error(RAP_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[1]);
        return RAP_CONF_ERROR;
    }

    if (plcf->sub == NULL) {
        plcf->sub = newSVpvn((char *) value[1].data, value[1].len);
    }

    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);
    clcf->handler = rap_http_perl_handler;

    return RAP_CONF_OK;
}


static char *
rap_http_perl_set(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_int_t                   index;
    rap_str_t                  *value;
    rap_http_variable_t        *v;
    rap_http_perl_variable_t   *pv;
    rap_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return RAP_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = rap_http_add_variable(cf, &value[1], RAP_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return RAP_CONF_ERROR;
    }

    pv = rap_palloc(cf->pool, sizeof(rap_http_perl_variable_t));
    if (pv == NULL) {
        return RAP_CONF_ERROR;
    }

    index = rap_http_get_variable_index(cf, &value[1]);
    if (index == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    pmcf = rap_http_conf_get_module_main_conf(cf, rap_http_perl_module);

    if (pmcf->perl == NULL) {
        if (rap_http_perl_init_interpreter(cf, pmcf) != RAP_CONF_OK) {
            return RAP_CONF_ERROR;
        }
    }

    pv->handler = value[2];

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    rap_http_perl_eval_anon_sub(aTHX_ &value[2], &pv->sub);

    if (pv->sub == &PL_sv_undef) {
        rap_conf_log_error(RAP_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[2]);
        return RAP_CONF_ERROR;
    }

    if (pv->sub == NULL) {
        pv->sub = newSVpvn((char *) value[2].data, value[2].len);
    }

    }

    v->get_handler = rap_http_perl_variable;
    v->data = (uintptr_t) pv;

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_perl_init_worker(rap_cycle_t *cycle)
{
    rap_http_perl_main_conf_t  *pmcf;

    pmcf = rap_http_cycle_get_module_main_conf(cycle, rap_http_perl_module);

    if (pmcf) {
        dTHXa(pmcf->perl);
        PERL_SET_CONTEXT(pmcf->perl);
        PERL_SET_INTERP(pmcf->perl);

        /* set worker's $$ */

        sv_setiv(GvSV(gv_fetchpv("$", TRUE, SVt_PV)), (I32) rap_pid);
    }

    return RAP_OK;
}


static void
rap_http_perl_exit(rap_cycle_t *cycle)
{
#if (RAP_HAVE_PERL_MULTIPLICITY)

    /*
     * the master exit hook is run before global pool cleanup,
     * therefore just set flag here
     */

    rap_perl_term = 1;

#else

    if (rap_stash) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, cycle->log, 0, "perl term");

        (void) perl_destruct(perl);

        perl_free(perl);

        PERL_SYS_TERM();
    }

#endif
}
