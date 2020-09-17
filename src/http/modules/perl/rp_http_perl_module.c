
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rp_http_perl_module.h>


typedef struct {
    PerlInterpreter   *perl;
    HV                *rap;
    rp_array_t       *modules;
    rp_array_t       *requires;
} rp_http_perl_main_conf_t;


typedef struct {
    SV                *sub;
    rp_str_t          handler;
} rp_http_perl_loc_conf_t;


typedef struct {
    SV                *sub;
    rp_str_t          handler;
} rp_http_perl_variable_t;


#if (RP_HTTP_SSI)
static rp_int_t rp_http_perl_ssi(rp_http_request_t *r,
    rp_http_ssi_ctx_t *ssi_ctx, rp_str_t **params);
#endif

static char *rp_http_perl_init_interpreter(rp_conf_t *cf,
    rp_http_perl_main_conf_t *pmcf);
static PerlInterpreter *rp_http_perl_create_interpreter(rp_conf_t *cf,
    rp_http_perl_main_conf_t *pmcf);
static rp_int_t rp_http_perl_run_requires(pTHX_ rp_array_t *requires,
    rp_log_t *log);
static rp_int_t rp_http_perl_call_handler(pTHX_ rp_http_request_t *r,
    rp_http_perl_ctx_t *ctx, HV *rap, SV *sub, SV **args,
    rp_str_t *handler, rp_str_t *rv);
static void rp_http_perl_eval_anon_sub(pTHX_ rp_str_t *handler, SV **sv);

static rp_int_t rp_http_perl_preconfiguration(rp_conf_t *cf);
static void *rp_http_perl_create_main_conf(rp_conf_t *cf);
static char *rp_http_perl_init_main_conf(rp_conf_t *cf, void *conf);
static void *rp_http_perl_create_loc_conf(rp_conf_t *cf);
static char *rp_http_perl_merge_loc_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_http_perl(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_http_perl_set(rp_conf_t *cf, rp_command_t *cmd, void *conf);

#if (RP_HAVE_PERL_MULTIPLICITY)
static void rp_http_perl_cleanup_perl(void *data);
#endif

static rp_int_t rp_http_perl_init_worker(rp_cycle_t *cycle);
static void rp_http_perl_exit(rp_cycle_t *cycle);


static rp_command_t  rp_http_perl_commands[] = {

    { rp_string("perl_modules"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_perl_main_conf_t, modules),
      NULL },

    { rp_string("perl_require"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_array_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_perl_main_conf_t, requires),
      NULL },

    { rp_string("perl"),
      RP_HTTP_LOC_CONF|RP_HTTP_LMT_CONF|RP_CONF_TAKE1,
      rp_http_perl,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("perl_set"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE2,
      rp_http_perl_set,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_perl_module_ctx = {
    rp_http_perl_preconfiguration,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rp_http_perl_create_main_conf,        /* create main configuration */
    rp_http_perl_init_main_conf,          /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_perl_create_loc_conf,         /* create location configuration */
    rp_http_perl_merge_loc_conf           /* merge location configuration */
};


rp_module_t  rp_http_perl_module = {
    RP_MODULE_V1,
    &rp_http_perl_module_ctx,             /* module context */
    rp_http_perl_commands,                /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    rp_http_perl_init_worker,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    rp_http_perl_exit,                    /* exit master */
    RP_MODULE_V1_PADDING
};


#if (RP_HTTP_SSI)

#define RP_HTTP_PERL_SSI_SUB  0
#define RP_HTTP_PERL_SSI_ARG  1


static rp_http_ssi_param_t  rp_http_perl_ssi_params[] = {
    { rp_string("sub"), RP_HTTP_PERL_SSI_SUB, 1, 0 },
    { rp_string("arg"), RP_HTTP_PERL_SSI_ARG, 0, 1 },
    { rp_null_string, 0, 0, 0 }
};

static rp_http_ssi_command_t  rp_http_perl_ssi_command = {
    rp_string("perl"), rp_http_perl_ssi, rp_http_perl_ssi_params, 0, 0, 1
};

#endif


static rp_str_t         rp_null_name = rp_null_string;
static HV               *rap_stash;

#if (RP_HAVE_PERL_MULTIPLICITY)
static rp_uint_t        rp_perl_term;
#else
static PerlInterpreter  *perl;
#endif


static void
rp_http_perl_xs_init(pTHX)
{
    newXS("DynaLoader::boot_DynaLoader", boot_DynaLoader, __FILE__);

    rap_stash = gv_stashpv("rap", TRUE);
}


static rp_int_t
rp_http_perl_handler(rp_http_request_t *r)
{
    r->main->count++;

    rp_http_perl_handle_request(r);

    return RP_DONE;
}


void
rp_http_perl_handle_request(rp_http_request_t *r)
{
    SV                         *sub;
    rp_int_t                   rc;
    rp_str_t                   uri, args, *handler;
    rp_uint_t                  flags;
    rp_http_perl_ctx_t        *ctx;
    rp_http_perl_loc_conf_t   *plcf;
    rp_http_perl_main_conf_t  *pmcf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0, "perl handler");

    ctx = rp_http_get_module_ctx(r, rp_http_perl_module);

    if (ctx == NULL) {
        ctx = rp_pcalloc(r->pool, sizeof(rp_http_perl_ctx_t));
        if (ctx == NULL) {
            rp_http_finalize_request(r, RP_ERROR);
            return;
        }

        rp_http_set_ctx(r, ctx, rp_http_perl_module);

        ctx->request = r;
    }

    pmcf = rp_http_get_module_main_conf(r, rp_http_perl_module);

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    if (ctx->next == NULL) {
        plcf = rp_http_get_module_loc_conf(r, rp_http_perl_module);
        sub = plcf->sub;
        handler = &plcf->handler;

    } else {
        sub = ctx->next;
        handler = &rp_null_name;
        ctx->next = NULL;
    }

    rc = rp_http_perl_call_handler(aTHX_ r, ctx, pmcf->rap, sub, NULL,
                                    handler, NULL);

    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl handler done: %i", rc);

    if (rc > 600) {
        rc = RP_OK;
    }

    if (ctx->redirect_uri.len) {
        uri = ctx->redirect_uri;

    } else {
        uri.len = 0;
    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;

    if (rc == RP_ERROR) {
        rp_http_finalize_request(r, rc);
        return;
    }

    if (ctx->done || ctx->next) {
        rp_http_finalize_request(r, RP_DONE);
        return;
    }

    if (uri.len) {
        if (uri.data[0] == '@') {
            rp_http_named_location(r, &uri);

        } else {
            rp_str_null(&args);
            flags = RP_HTTP_LOG_UNSAFE;

            if (rp_http_parse_unsafe_uri(r, &uri, &args, &flags) != RP_OK) {
                rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }

            rp_http_internal_redirect(r, &uri, &args);
        }

        rp_http_finalize_request(r, RP_DONE);
        return;
    }

    if (rc == RP_OK || rc == RP_HTTP_OK) {
        rp_http_send_special(r, RP_HTTP_LAST);
        ctx->done = 1;
    }

    rp_http_finalize_request(r, rc);
}


void
rp_http_perl_sleep_handler(rp_http_request_t *r)
{
    rp_event_t  *wev;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl sleep handler");

    wev = r->connection->write;

    if (wev->delayed) {

        if (rp_handle_write_event(wev, 0) != RP_OK) {
            rp_http_finalize_request(r, RP_HTTP_INTERNAL_SERVER_ERROR);
        }

        return;
    }

    rp_http_perl_handle_request(r);
}


static rp_int_t
rp_http_perl_variable(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    rp_http_perl_variable_t *pv = (rp_http_perl_variable_t *) data;

    rp_int_t                   rc;
    rp_str_t                   value;
    rp_uint_t                  saved;
    rp_http_perl_ctx_t        *ctx;
    rp_http_perl_main_conf_t  *pmcf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable handler");

    ctx = rp_http_get_module_ctx(r, rp_http_perl_module);

    if (ctx == NULL) {
        ctx = rp_pcalloc(r->pool, sizeof(rp_http_perl_ctx_t));
        if (ctx == NULL) {
            return RP_ERROR;
        }

        rp_http_set_ctx(r, ctx, rp_http_perl_module);

        ctx->request = r;
    }

    saved = ctx->variable;
    ctx->variable = 1;

    pmcf = rp_http_get_module_main_conf(r, rp_http_perl_module);

    value.data = NULL;

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    rc = rp_http_perl_call_handler(aTHX_ r, ctx, pmcf->rap, pv->sub, NULL,
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

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl variable done");

    return rc;
}


#if (RP_HTTP_SSI)

static rp_int_t
rp_http_perl_ssi(rp_http_request_t *r, rp_http_ssi_ctx_t *ssi_ctx,
    rp_str_t **params)
{
    SV                         *sv, **asv;
    rp_int_t                   rc;
    rp_str_t                  *handler, **args;
    rp_uint_t                  i;
    rp_http_perl_ctx_t        *ctx;
    rp_http_perl_main_conf_t  *pmcf;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "perl ssi handler");

    ctx = rp_http_get_module_ctx(r, rp_http_perl_module);

    if (ctx == NULL) {
        ctx = rp_pcalloc(r->pool, sizeof(rp_http_perl_ctx_t));
        if (ctx == NULL) {
            return RP_ERROR;
        }

        rp_http_set_ctx(r, ctx, rp_http_perl_module);

        ctx->request = r;
    }

    pmcf = rp_http_get_module_main_conf(r, rp_http_perl_module);

    ctx->ssi = ssi_ctx;
    ctx->header_sent = 1;

    handler = params[RP_HTTP_PERL_SSI_SUB];
    handler->data[handler->len] = '\0';

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

#if 0

    /* the code is disabled to force the precompiled perl code using only */

    rp_http_perl_eval_anon_sub(aTHX_ handler, &sv);

    if (sv == &PL_sv_undef) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "eval_pv(\"%V\") failed", handler);
        return RP_ERROR;
    }

    if (sv == NULL) {
        sv = newSVpvn((char *) handler->data, handler->len);
    }

#endif

    sv = newSVpvn((char *) handler->data, handler->len);

    args = &params[RP_HTTP_PERL_SSI_ARG];

    if (args[0]) {

        for (i = 0; args[i]; i++) { /* void */ }

        asv = rp_pcalloc(r->pool, (i + 1) * sizeof(SV *));

        if (asv == NULL) {
            SvREFCNT_dec(sv);
            return RP_ERROR;
        }

        asv[0] = (SV *) (uintptr_t) i;

        for (i = 0; args[i]; i++) {
            asv[i + 1] = newSVpvn((char *) args[i]->data, args[i]->len);
        }

    } else {
        asv = NULL;
    }

    rc = rp_http_perl_call_handler(aTHX_ r, ctx, pmcf->rap, sv, asv,
                                    handler, NULL);

    SvREFCNT_dec(sv);

    }

    ctx->filename.data = NULL;
    ctx->redirect_uri.len = 0;
    ctx->ssi = NULL;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0, "perl ssi done");

    return rc;
}

#endif


static char *
rp_http_perl_init_interpreter(rp_conf_t *cf, rp_http_perl_main_conf_t *pmcf)
{
    rp_str_t           *m;
    rp_uint_t           i;
#if (RP_HAVE_PERL_MULTIPLICITY)
    rp_pool_cleanup_t  *cln;

    cln = rp_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return RP_CONF_ERROR;
    }

#endif

#ifdef RP_PERL_MODULES
    if (pmcf->modules == RP_CONF_UNSET_PTR) {

        pmcf->modules = rp_array_create(cf->pool, 1, sizeof(rp_str_t));
        if (pmcf->modules == NULL) {
            return RP_CONF_ERROR;
        }

        m = rp_array_push(pmcf->modules);
        if (m == NULL) {
            return RP_CONF_ERROR;
        }

        rp_str_set(m, RP_PERL_MODULES);
    }
#endif

    if (pmcf->modules != RP_CONF_UNSET_PTR) {
        m = pmcf->modules->elts;
        for (i = 0; i < pmcf->modules->nelts; i++) {
            if (rp_conf_full_name(cf->cycle, &m[i], 0) != RP_OK) {
                return RP_CONF_ERROR;
            }
        }
    }

#if !(RP_HAVE_PERL_MULTIPLICITY)

    if (perl) {

        if (rp_set_environment(cf->cycle, NULL) == NULL) {
            return RP_CONF_ERROR;
        }

        if (rp_http_perl_run_requires(aTHX_ pmcf->requires, cf->log)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }

        pmcf->perl = perl;
        pmcf->rap = rap_stash;

        return RP_CONF_OK;
    }

#endif

    if (rap_stash == NULL) {
        PERL_SYS_INIT(&rp_argc, &rp_argv);
    }

    pmcf->perl = rp_http_perl_create_interpreter(cf, pmcf);

    if (pmcf->perl == NULL) {
        return RP_CONF_ERROR;
    }

    pmcf->rap = rap_stash;

#if (RP_HAVE_PERL_MULTIPLICITY)

    cln->handler = rp_http_perl_cleanup_perl;
    cln->data = pmcf->perl;

#else

    perl = pmcf->perl;

#endif

    return RP_CONF_OK;
}


static PerlInterpreter *
rp_http_perl_create_interpreter(rp_conf_t *cf,
    rp_http_perl_main_conf_t *pmcf)
{
    int                n;
    STRLEN             len;
    SV                *sv;
    char              *ver, **embedding;
    rp_str_t         *m;
    rp_uint_t         i;
    PerlInterpreter   *perl;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, cf->log, 0, "create perl interpreter");

    if (rp_set_environment(cf->cycle, NULL) == NULL) {
        return NULL;
    }

    perl = perl_alloc();
    if (perl == NULL) {
        rp_log_error(RP_LOG_ALERT, cf->log, 0, "perl_alloc() failed");
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

    n = (pmcf->modules != RP_CONF_UNSET_PTR) ? pmcf->modules->nelts * 2 : 0;

    embedding = rp_palloc(cf->pool, (5 + n) * sizeof(char *));
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

    n = perl_parse(perl, rp_http_perl_xs_init, n, embedding, NULL);

    if (n != 0) {
        rp_log_error(RP_LOG_ALERT, cf->log, 0, "perl_parse() failed: %d", n);
        goto fail;
    }

    sv = get_sv("rap::VERSION", FALSE);
    ver = SvPV(sv, len);

    if (rp_strcmp(ver, RAP_VERSION) != 0) {
        rp_log_error(RP_LOG_ALERT, cf->log, 0,
                      "version " RAP_VERSION " of rap.pm is required, "
                      "but %s was found", ver);
        goto fail;
    }

    if (rp_http_perl_run_requires(aTHX_ pmcf->requires, cf->log) != RP_OK) {
        goto fail;
    }

    }

    return perl;

fail:

    (void) perl_destruct(perl);

    perl_free(perl);

    return NULL;
}


static rp_int_t
rp_http_perl_run_requires(pTHX_ rp_array_t *requires, rp_log_t *log)
{
    u_char      *err;
    STRLEN       len;
    rp_str_t   *script;
    rp_uint_t   i;

    if (requires == RP_CONF_UNSET_PTR) {
        return RP_OK;
    }

    script = requires->elts;
    for (i = 0; i < requires->nelts; i++) {

        require_pv((char *) script[i].data);

        if (SvTRUE(ERRSV)) {

            err = (u_char *) SvPV(ERRSV, len);
            while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

            rp_log_error(RP_LOG_EMERG, log, 0,
                          "require_pv(\"%s\") failed: \"%*s\"",
                          script[i].data, len + 1, err);

            return RP_ERROR;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_perl_call_handler(pTHX_ rp_http_request_t *r,
    rp_http_perl_ctx_t *ctx, HV *rap, SV *sub, SV **args,
    rp_str_t *handler, rp_str_t *rv)
{
    SV                *sv;
    int                n, status;
    char              *line;
    u_char            *err;
    STRLEN             len, n_a;
    rp_uint_t         i;
    rp_connection_t  *c;

    dSP;

    status = 0;

    ctx->error = 0;
    ctx->status = RP_OK;

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

            rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                           "call_sv: %d", status);

        } else {
            line = SvPVx(POPs, n_a);
            rv->len = n_a;

            rv->data = rp_pnalloc(r->pool, n_a);
            if (rv->data == NULL) {
                return RP_ERROR;
            }

            rp_memcpy(rv->data, line, n_a);
        }
    }

    PUTBACK;

    FREETMPS;
    LEAVE;

    if (ctx->error) {

        rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "call_sv: error, %d", ctx->status);

        if (ctx->status != RP_OK) {
            return ctx->status;
        }

        return RP_ERROR;
    }

    /* check $@ */

    if (SvTRUE(ERRSV)) {

        err = (u_char *) SvPV(ERRSV, len);
        while (--len && (err[len] == CR || err[len] == LF)) { /* void */ }

        rp_log_error(RP_LOG_ERR, c->log, 0,
                      "call_sv(\"%V\") failed: \"%*s\"", handler, len + 1, err);

        if (rv) {
            return RP_ERROR;
        }

        ctx->redirect_uri.len = 0;

        if (ctx->header_sent) {
            return RP_ERROR;
        }

        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (n != 1) {
        rp_log_error(RP_LOG_ALERT, c->log, 0,
                      "call_sv(\"%V\") returned %d results", handler, n);
        status = RP_OK;
    }

    if (rv) {
        return RP_OK;
    }

    return (rp_int_t) status;
}


static void
rp_http_perl_eval_anon_sub(pTHX_ rp_str_t *handler, SV **sv)
{
    u_char  *p;

    for (p = handler->data; *p; p++) {
        if (*p != ' ' && *p != '\t' && *p != CR && *p != LF) {
            break;
        }
    }

    if (rp_strncmp(p, "sub ", 4) == 0
        || rp_strncmp(p, "sub{", 4) == 0
        || rp_strncmp(p, "use ", 4) == 0)
    {
        *sv = eval_pv((char *) p, FALSE);

        /* eval_pv() does not set ERRSV on failure */

        return;
    }

    *sv = NULL;
}


static void *
rp_http_perl_create_main_conf(rp_conf_t *cf)
{
    rp_http_perl_main_conf_t  *pmcf;

    pmcf = rp_pcalloc(cf->pool, sizeof(rp_http_perl_main_conf_t));
    if (pmcf == NULL) {
        return NULL;
    }

    pmcf->modules = RP_CONF_UNSET_PTR;
    pmcf->requires = RP_CONF_UNSET_PTR;

    return pmcf;
}


static char *
rp_http_perl_init_main_conf(rp_conf_t *cf, void *conf)
{
    rp_http_perl_main_conf_t *pmcf = conf;

    if (pmcf->perl == NULL) {
        if (rp_http_perl_init_interpreter(cf, pmcf) != RP_CONF_OK) {
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}


#if (RP_HAVE_PERL_MULTIPLICITY)

static void
rp_http_perl_cleanup_perl(void *data)
{
    PerlInterpreter  *perl = data;

    PERL_SET_CONTEXT(perl);
    PERL_SET_INTERP(perl);

    (void) perl_destruct(perl);

    perl_free(perl);

    if (rp_perl_term) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, rp_cycle->log, 0, "perl term");

        PERL_SYS_TERM();
    }
}

#endif


static rp_int_t
rp_http_perl_preconfiguration(rp_conf_t *cf)
{
#if (RP_HTTP_SSI)
    rp_int_t                  rc;
    rp_http_ssi_main_conf_t  *smcf;

    smcf = rp_http_conf_get_module_main_conf(cf, rp_http_ssi_filter_module);

    rc = rp_hash_add_key(&smcf->commands, &rp_http_perl_ssi_command.name,
                          &rp_http_perl_ssi_command, RP_HASH_READONLY_KEY);

    if (rc != RP_OK) {
        if (rc == RP_BUSY) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "conflicting SSI command \"%V\"",
                               &rp_http_perl_ssi_command.name);
        }

        return RP_ERROR;
    }
#endif

    return RP_OK;
}


static void *
rp_http_perl_create_loc_conf(rp_conf_t *cf)
{
    rp_http_perl_loc_conf_t *plcf;

    plcf = rp_pcalloc(cf->pool, sizeof(rp_http_perl_loc_conf_t));
    if (plcf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     plcf->handler = { 0, NULL };
     */

    return plcf;
}


static char *
rp_http_perl_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_perl_loc_conf_t *prev = parent;
    rp_http_perl_loc_conf_t *conf = child;

    if (conf->sub == NULL) {
        conf->sub = prev->sub;
        conf->handler = prev->handler;
    }

    return RP_CONF_OK;
}


static char *
rp_http_perl(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_perl_loc_conf_t *plcf = conf;

    rp_str_t                  *value;
    rp_http_core_loc_conf_t   *clcf;
    rp_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (plcf->handler.data) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "duplicate perl handler \"%V\"", &value[1]);
        return RP_CONF_ERROR;
    }

    pmcf = rp_http_conf_get_module_main_conf(cf, rp_http_perl_module);

    if (pmcf->perl == NULL) {
        if (rp_http_perl_init_interpreter(cf, pmcf) != RP_CONF_OK) {
            return RP_CONF_ERROR;
        }
    }

    plcf->handler = value[1];

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    rp_http_perl_eval_anon_sub(aTHX_ &value[1], &plcf->sub);

    if (plcf->sub == &PL_sv_undef) {
        rp_conf_log_error(RP_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[1]);
        return RP_CONF_ERROR;
    }

    if (plcf->sub == NULL) {
        plcf->sub = newSVpvn((char *) value[1].data, value[1].len);
    }

    }

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);
    clcf->handler = rp_http_perl_handler;

    return RP_CONF_OK;
}


static char *
rp_http_perl_set(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_int_t                   index;
    rp_str_t                  *value;
    rp_http_variable_t        *v;
    rp_http_perl_variable_t   *pv;
    rp_http_perl_main_conf_t  *pmcf;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return RP_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = rp_http_add_variable(cf, &value[1], RP_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return RP_CONF_ERROR;
    }

    pv = rp_palloc(cf->pool, sizeof(rp_http_perl_variable_t));
    if (pv == NULL) {
        return RP_CONF_ERROR;
    }

    index = rp_http_get_variable_index(cf, &value[1]);
    if (index == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    pmcf = rp_http_conf_get_module_main_conf(cf, rp_http_perl_module);

    if (pmcf->perl == NULL) {
        if (rp_http_perl_init_interpreter(cf, pmcf) != RP_CONF_OK) {
            return RP_CONF_ERROR;
        }
    }

    pv->handler = value[2];

    {

    dTHXa(pmcf->perl);
    PERL_SET_CONTEXT(pmcf->perl);
    PERL_SET_INTERP(pmcf->perl);

    rp_http_perl_eval_anon_sub(aTHX_ &value[2], &pv->sub);

    if (pv->sub == &PL_sv_undef) {
        rp_conf_log_error(RP_LOG_ERR, cf, 0,
                           "eval_pv(\"%V\") failed", &value[2]);
        return RP_CONF_ERROR;
    }

    if (pv->sub == NULL) {
        pv->sub = newSVpvn((char *) value[2].data, value[2].len);
    }

    }

    v->get_handler = rp_http_perl_variable;
    v->data = (uintptr_t) pv;

    return RP_CONF_OK;
}


static rp_int_t
rp_http_perl_init_worker(rp_cycle_t *cycle)
{
    rp_http_perl_main_conf_t  *pmcf;

    pmcf = rp_http_cycle_get_module_main_conf(cycle, rp_http_perl_module);

    if (pmcf) {
        dTHXa(pmcf->perl);
        PERL_SET_CONTEXT(pmcf->perl);
        PERL_SET_INTERP(pmcf->perl);

        /* set worker's $$ */

        sv_setiv(GvSV(gv_fetchpv("$", TRUE, SVt_PV)), (I32) rp_pid);
    }

    return RP_OK;
}


static void
rp_http_perl_exit(rp_cycle_t *cycle)
{
#if (RP_HAVE_PERL_MULTIPLICITY)

    /*
     * the master exit hook is run before global pool cleanup,
     * therefore just set flag here
     */

    rp_perl_term = 1;

#else

    if (rap_stash) {
        rp_log_debug0(RP_LOG_DEBUG_HTTP, cycle->log, 0, "perl term");

        (void) perl_destruct(perl);

        perl_free(perl);

        PERL_SYS_TERM();
    }

#endif
}
