
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


typedef struct {
    rap_flag_t  pcre_jit;
} rap_regex_conf_t;


static void * rap_libc_cdecl rap_regex_malloc(size_t size);
static void rap_libc_cdecl rap_regex_free(void *p);
#if (RAP_HAVE_PCRE_JIT)
static void rap_pcre_free_studies(void *data);
#endif

static rap_int_t rap_regex_module_init(rap_cycle_t *cycle);

static void *rap_regex_create_conf(rap_cycle_t *cycle);
static char *rap_regex_init_conf(rap_cycle_t *cycle, void *conf);

static char *rap_regex_pcre_jit(rap_conf_t *cf, void *post, void *data);
static rap_conf_post_t  rap_regex_pcre_jit_post = { rap_regex_pcre_jit };


static rap_command_t  rap_regex_commands[] = {

    { rap_string("pcre_jit"),
      RAP_MAIN_CONF|RAP_DIRECT_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      0,
      offsetof(rap_regex_conf_t, pcre_jit),
      &rap_regex_pcre_jit_post },

      rap_null_command
};


static rap_core_module_t  rap_regex_module_ctx = {
    rap_string("regex"),
    rap_regex_create_conf,
    rap_regex_init_conf
};


rap_module_t  rap_regex_module = {
    RAP_MODULE_V1,
    &rap_regex_module_ctx,                 /* module context */
    rap_regex_commands,                    /* module directives */
    RAP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    rap_regex_module_init,                 /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_pool_t  *rap_pcre_pool;
static rap_list_t  *rap_pcre_studies;


void
rap_regex_init(void)
{
    pcre_malloc = rap_regex_malloc;
    pcre_free = rap_regex_free;
}


static rap_inline void
rap_regex_malloc_init(rap_pool_t *pool)
{
    rap_pcre_pool = pool;
}


static rap_inline void
rap_regex_malloc_done(void)
{
    rap_pcre_pool = NULL;
}


rap_int_t
rap_regex_compile(rap_regex_compile_t *rc)
{
    int               n, erroff;
    char             *p;
    pcre             *re;
    const char       *errstr;
    rap_regex_elt_t  *elt;

    rap_regex_malloc_init(rc->pool);

    re = pcre_compile((const char *) rc->pattern.data, (int) rc->options,
                      &errstr, &erroff, NULL);

    /* ensure that there is no current pool */
    rap_regex_malloc_done();

    if (re == NULL) {
        if ((size_t) erroff == rc->pattern.len) {
           rc->err.len = rap_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\"",
                               errstr, &rc->pattern)
                      - rc->err.data;

        } else {
           rc->err.len = rap_snprintf(rc->err.data, rc->err.len,
                              "pcre_compile() failed: %s in \"%V\" at \"%s\"",
                               errstr, &rc->pattern, rc->pattern.data + erroff)
                      - rc->err.data;
        }

        return RAP_ERROR;
    }

    rc->regex = rap_pcalloc(rc->pool, sizeof(rap_regex_t));
    if (rc->regex == NULL) {
        goto nomem;
    }

    rc->regex->code = re;

    /* do not study at runtime */

    if (rap_pcre_studies != NULL) {
        elt = rap_list_push(rap_pcre_studies);
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
        return RAP_OK;
    }

    n = pcre_fullinfo(re, NULL, PCRE_INFO_NAMECOUNT, &rc->named_captures);
    if (n < 0) {
        p = "pcre_fullinfo(\"%V\", PCRE_INFO_NAMECOUNT) failed: %d";
        goto failed;
    }

    if (rc->named_captures == 0) {
        return RAP_OK;
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

    return RAP_OK;

failed:

    rc->err.len = rap_snprintf(rc->err.data, rc->err.len, p, &rc->pattern, n)
                  - rc->err.data;
    return RAP_ERROR;

nomem:

    rc->err.len = rap_snprintf(rc->err.data, rc->err.len,
                               "regex \"%V\" compilation failed: no memory",
                               &rc->pattern)
                  - rc->err.data;
    return RAP_ERROR;
}


rap_int_t
rap_regex_exec_array(rap_array_t *a, rap_str_t *s, rap_log_t *log)
{
    rap_int_t         n;
    rap_uint_t        i;
    rap_regex_elt_t  *re;

    re = a->elts;

    for (i = 0; i < a->nelts; i++) {

        n = rap_regex_exec(re[i].regex, s, NULL, 0);

        if (n == RAP_REGEX_NO_MATCHED) {
            continue;
        }

        if (n < 0) {
            rap_log_error(RAP_LOG_ALERT, log, 0,
                          rap_regex_exec_n " failed: %i on \"%V\" using \"%s\"",
                          n, s, re[i].name);
            return RAP_ERROR;
        }

        /* match */

        return RAP_OK;
    }

    return RAP_DECLINED;
}


static void * rap_libc_cdecl
rap_regex_malloc(size_t size)
{
    rap_pool_t      *pool;
    pool = rap_pcre_pool;

    if (pool) {
        return rap_palloc(pool, size);
    }

    return NULL;
}


static void rap_libc_cdecl
rap_regex_free(void *p)
{
    return;
}


#if (RAP_HAVE_PCRE_JIT)

static void
rap_pcre_free_studies(void *data)
{
    rap_list_t *studies = data;

    rap_uint_t        i;
    rap_list_part_t  *part;
    rap_regex_elt_t  *elts;

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


static rap_int_t
rap_regex_module_init(rap_cycle_t *cycle)
{
    int               opt;
    const char       *errstr;
    rap_uint_t        i;
    rap_list_part_t  *part;
    rap_regex_elt_t  *elts;

    opt = 0;

#if (RAP_HAVE_PCRE_JIT)
    {
    rap_regex_conf_t    *rcf;
    rap_pool_cleanup_t  *cln;

    rcf = (rap_regex_conf_t *) rap_get_conf(cycle->conf_ctx, rap_regex_module);

    if (rcf->pcre_jit) {
        opt = PCRE_STUDY_JIT_COMPILE;

        /*
         * The PCRE JIT compiler uses mmap for its executable codes, so we
         * have to explicitly call the pcre_free_study() function to free
         * this memory.
         */

        cln = rap_pool_cleanup_add(cycle->pool, 0);
        if (cln == NULL) {
            return RAP_ERROR;
        }

        cln->handler = rap_pcre_free_studies;
        cln->data = rap_pcre_studies;
    }
    }
#endif

    rap_regex_malloc_init(cycle->pool);

    part = &rap_pcre_studies->part;
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
            rap_log_error(RAP_LOG_ALERT, cycle->log, 0,
                          "pcre_study() failed: %s in \"%s\"",
                          errstr, elts[i].name);
        }

#if (RAP_HAVE_PCRE_JIT)
        if (opt & PCRE_STUDY_JIT_COMPILE) {
            int jit, n;

            jit = 0;
            n = pcre_fullinfo(elts[i].regex->code, elts[i].regex->extra,
                              PCRE_INFO_JIT, &jit);

            if (n != 0 || jit != 1) {
                rap_log_error(RAP_LOG_INFO, cycle->log, 0,
                              "JIT compiler does not support pattern: \"%s\"",
                              elts[i].name);
            }
        }
#endif
    }

    rap_regex_malloc_done();

    rap_pcre_studies = NULL;

    return RAP_OK;
}


static void *
rap_regex_create_conf(rap_cycle_t *cycle)
{
    rap_regex_conf_t  *rcf;

    rcf = rap_pcalloc(cycle->pool, sizeof(rap_regex_conf_t));
    if (rcf == NULL) {
        return NULL;
    }

    rcf->pcre_jit = RAP_CONF_UNSET;

    rap_pcre_studies = rap_list_create(cycle->pool, 8, sizeof(rap_regex_elt_t));
    if (rap_pcre_studies == NULL) {
        return NULL;
    }

    return rcf;
}


static char *
rap_regex_init_conf(rap_cycle_t *cycle, void *conf)
{
    rap_regex_conf_t *rcf = conf;

    rap_conf_init_value(rcf->pcre_jit, 0);

    return RAP_CONF_OK;
}


static char *
rap_regex_pcre_jit(rap_conf_t *cf, void *post, void *data)
{
    rap_flag_t  *fp = data;

    if (*fp == 0) {
        return RAP_CONF_OK;
    }

#if (RAP_HAVE_PCRE_JIT)
    {
    int  jit, r;

    jit = 0;
    r = pcre_config(PCRE_CONFIG_JIT, &jit);

    if (r != 0 || jit != 1) {
        rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                           "PCRE library does not support JIT");
        *fp = 0;
    }
    }
#else
    rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                       "rap was built without PCRE JIT support");
    *fp = 0;
#endif

    return RAP_CONF_OK;
}
