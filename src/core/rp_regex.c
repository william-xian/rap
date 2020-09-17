
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


typedef struct {
    rp_flag_t  pcre_jit;
} rp_regex_conf_t;


static void * rp_libc_cdecl rp_regex_malloc(size_t size);
static void rp_libc_cdecl rp_regex_free(void *p);
#if (RP_HAVE_PCRE_JIT)
static void rp_pcre_free_studies(void *data);
#endif

static rp_int_t rp_regex_module_init(rp_cycle_t *cycle);

static void *rp_regex_create_conf(rp_cycle_t *cycle);
static char *rp_regex_init_conf(rp_cycle_t *cycle, void *conf);

static char *rp_regex_pcre_jit(rp_conf_t *cf, void *post, void *data);
static rp_conf_post_t  rp_regex_pcre_jit_post = { rp_regex_pcre_jit };


static rp_command_t  rp_regex_commands[] = {

    { rp_string("pcre_jit"),
      RP_MAIN_CONF|RP_DIRECT_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      0,
      offsetof(rp_regex_conf_t, pcre_jit),
      &rp_regex_pcre_jit_post },

      rp_null_command
};


static rp_core_module_t  rp_regex_module_ctx = {
    rp_string("regex"),
    rp_regex_create_conf,
    rp_regex_init_conf
};


rp_module_t  rp_regex_module = {
    RP_MODULE_V1,
    &rp_regex_module_ctx,                 /* module context */
    rp_regex_commands,                    /* module directives */
    RP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    rp_regex_module_init,                 /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_pool_t  *rp_pcre_pool;
static rp_list_t  *rp_pcre_studies;


void
rp_regex_init(void)
{
    pcre_malloc = rp_regex_malloc;
    pcre_free = rp_regex_free;
}


static rp_inline void
rp_regex_malloc_init(rp_pool_t *pool)
{
    rp_pcre_pool = pool;
}


static rp_inline void
rp_regex_malloc_done(void)
{
    rp_pcre_pool = NULL;
}


rp_int_t
rp_regex_compile(rp_regex_compile_t *rc)
{
    int               n, erroff;
    char             *p;
    pcre             *re;
    const char       *errstr;
    rp_regex_elt_t  *elt;

    rp_regex_malloc_init(rc->pool);

    re = pcre_compile((const char *) rc->pattern.data, (int) rc->options,
                      &errstr, &erroff, NULL);

    /* ensure that there is no current pool */
    rp_regex_malloc_done();

    if (re == NULL) {
        if ((size_t) erroff == rc->pattern.len) {
           rc->err.len = rp_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\"",
                               errstr, &rc->pattern)
                      - rc->err.data;

        } else {
           rc->err.len = rp_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\" at \"%s\"",
                               errstr, &rc->pattern, rc->pattern.data + erroff)
                      - rc->err.data;
        }

        return RP_ERROR;
    }

    rc->regex = rp_pcalloc(rc->pool, sizeof(rp_regex_t));
    if (rc->regex == NULL) {
        goto nomem;
    }

    rc->regex->code = re;

    /* do not study at runtime */

    if (rp_pcre_studies != NULL) {
        elt = rp_list_push(rp_pcre_studies);
        if (elt == NULL) {
            goto nomem;
        }

        elt->regex = rc->regex;
        elt->name = rc->pattern.data;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_CAPTURECOUNT, &rc->captures);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_CAPTURECOUNT) failed: %d";
        goto failed;
    }

    if (rc->captures == 0) {
        return RP_OK;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMECOUNT, &rc->named_captures);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMECOUNT) failed: %d";
        goto failed;
    }

    if (rc->named_captures == 0) {
        return RP_OK;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMEENTRYSIZE, &rc->name_size);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMEENTRYSIZE) failed: %d";
        goto failed;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMETABLE, &rc->names);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMETABLE) failed: %d";
        goto failed;
    }

    return RP_OK;

failed:

    rc->err.len = rp_snprintf(rc->err.data, rc->err.len, p, &rc->pattern, n)
                  - rc->err.data;
    return RP_ERROR;

nomem:

    rc->err.len = rp_snprintf(rc->err.data, rc->err.len,
                               "regex \"%V\" compilation failed: no memory",
                               &rc->pattern)
                  - rc->err.data;
    return RP_ERROR;
}


rp_int_t
rp_regex_exec_array(rp_array_t *a, rp_str_t *s, rp_log_t *log)
{
    rp_int_t         n;
    rp_uint_t        i;
    rp_regex_elt_t  *re;

    re = a->elts;

    for (i = 0; i < a->nelts; i++) {

        n = rp_regex_exec(re[i].regex, s, NULL, 0);

        if (n == RP_REGEX_NO_MATCHED) {
            continue;
        }

        if (n < 0) {
            rp_log_error(RP_LOG_ALERT, log, 0,
                          rp_regex_exec_n " failed: %i on \"%V\" using \"%s\"",
                          n, s, re[i].name);
            return RP_ERROR;
        }

        /* match */

        return RP_OK;
    }

    return RP_DECLINED;
}


static void * rp_libc_cdecl
rp_regex_malloc(size_t size)
{
    rp_pool_t      *pool;
    pool = rp_pcre_pool;

    if (pool) {
        return rp_palloc(pool, size);
    }

    return NULL;
}


static void rp_libc_cdecl
rp_regex_free(void *p)
{
    return;
}


#if (RP_HAVE_PCRE_JIT)

static void
rp_pcre_free_studies(void *data)
{
    rp_list_t *studies = data;

    rp_uint_t        i;
    rp_list_part_t  *part;
    rp_regex_elt_t  *elts;

    part = &studies->part;
    elts = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            elts = part->elts;
            i = 0;
        }

        if (elts[i].regex->extra != NULL) {
            pcre_free_study(elts[i].regex->extra);
        }
    }
}

#endif


static rp_int_t
rp_regex_module_init(rp_cycle_t *cycle)
{
    int               opt;
    const char       *errstr;
    rp_uint_t        i;
    rp_list_part_t  *part;
    rp_regex_elt_t  *elts;

    opt = 0;

#if (RP_HAVE_PCRE_JIT)
    {
    rp_regex_conf_t    *rcf;
    rp_pool_cleanup_t  *cln;

    rcf = (rp_regex_conf_t *) rp_get_conf(cycle->conf_ctx, rp_regex_module);

    if (rcf->pcre_jit) {
        opt = PCRE_STUDY_JIT_COMPILE;

        /*
         * The PCRE JIT compiler uses mmap for its executable codes, so we
         * have to explicitly call the pcre_free_study() function to free
         * this memory.
         */

        cln = rp_pool_cleanup_add(cycle->pool, 0);
        if (cln == NULL) {
            return RP_ERROR;
        }

        cln->handler = rp_pcre_free_studies;
        cln->data = rp_pcre_studies;
    }
    }
#endif

    rp_regex_malloc_init(cycle->pool);

    part = &rp_pcre_studies->part;
    elts = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            elts = part->elts;
            i = 0;
        }

        elts[i].regex->extra = pcre_study(elts[i].regex->code, opt, &errstr);

        if (errstr != NULL) {
            rp_log_error(RP_LOG_ALERT, cycle->log, 0,
                          "pcre_study() failed: %s in \"%s\"",
                          errstr, elts[i].name);
        }

#if (RP_HAVE_PCRE_JIT)
        if (opt & PCRE_STUDY_JIT_COMPILE) {
            int jit, n;

            jit = 0;
            n = pcre_fullinfo(elts[i].regex->code, elts[i].regex->extra,
                              PCRE_INFO_JIT, &jit);

            if (n != 0 || jit != 1) {
                rp_log_error(RP_LOG_INFO, cycle->log, 0,
                              "JIT compiler does not support pattern: \"%s\"",
                              elts[i].name);
            }
        }
#endif
    }

    rp_regex_malloc_done();

    rp_pcre_studies = NULL;

    return RP_OK;
}


static void *
rp_regex_create_conf(rp_cycle_t *cycle)
{
    rp_regex_conf_t  *rcf;

    rcf = rp_pcalloc(cycle->pool, sizeof(rp_regex_conf_t));
    if (rcf == NULL) {
        return NULL;
    }

    rcf->pcre_jit = RP_CONF_UNSET;

    rp_pcre_studies = rp_list_create(cycle->pool, 8, sizeof(rp_regex_elt_t));
    if (rp_pcre_studies == NULL) {
        return NULL;
    }

    return rcf;
}


static char *
rp_regex_init_conf(rp_cycle_t *cycle, void *conf)
{
    rp_regex_conf_t *rcf = conf;

    rp_conf_init_value(rcf->pcre_jit, 0);

    return RP_CONF_OK;
}


static char *
rp_regex_pcre_jit(rp_conf_t *cf, void *post, void *data)
{
    rp_flag_t  *fp = data;

    if (*fp == 0) {
        return RP_CONF_OK;
    }

#if (RP_HAVE_PCRE_JIT)
    {
    int  jit, r;

    jit = 0;
    r = pcre_config(PCRE_CONFIG_JIT, &jit);

    if (r != 0 || jit != 1) {
        rp_conf_log_error(RP_LOG_WARN, cf, 0,
                           "PCRE library does not support JIT");
        *fp = 0;
    }
    }
#else
    rp_conf_log_error(RP_LOG_WARN, cf, 0,
                       "rap was built without PCRE JIT support");
    *fp = 0;
#endif

    return RP_CONF_OK;
}
