
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_uint_t                  hash_max_size;
    rap_uint_t                  hash_bucket_size;
} rap_http_map_conf_t;


typedef struct {
    rap_hash_keys_arrays_t      keys;

    rap_array_t                *values_hash;
#if (RAP_PCRE)
    rap_array_t                 regexes;
#endif

    rap_http_variable_value_t  *default_value;
    rap_conf_t                 *cf;
    unsigned                    hostnames:1;
    unsigned                    no_cacheable:1;
} rap_http_map_conf_ctx_t;


typedef struct {
    rap_http_map_t              map;
    rap_http_complex_value_t    value;
    rap_http_variable_value_t  *default_value;
    rap_uint_t                  hostnames;      /* unsigned  hostnames:1 */
} rap_http_map_ctx_t;


static int rap_libc_cdecl rap_http_map_cmp_dns_wildcards(const void *one,
    const void *two);
static void *rap_http_map_create_conf(rap_conf_t *cf);
static char *rap_http_map_block(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static char *rap_http_map(rap_conf_t *cf, rap_command_t *dummy, void *conf);


static rap_command_t  rap_http_map_commands[] = {

    { rap_string("map"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_TAKE2,
      rap_http_map_block,
      RAP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rap_string("map_hash_max_size"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_map_conf_t, hash_max_size),
      NULL },

    { rap_string("map_hash_bucket_size"),
      RAP_HTTP_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rap_http_map_conf_t, hash_bucket_size),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_map_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_http_map_create_conf,              /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_map_module = {
    RAP_MODULE_V1,
    &rap_http_map_module_ctx,              /* module context */
    rap_http_map_commands,                 /* module directives */
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
rap_http_map_variable(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    rap_http_map_ctx_t  *map = (rap_http_map_ctx_t *) data;

    rap_str_t                   val, str;
    rap_http_complex_value_t   *cv;
    rap_http_variable_value_t  *value;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http map started");

    if (rap_http_complex_value(r, &map->value, &val) != RAP_OK) {
        return RAP_ERROR;
    }

    if (map->hostnames && val.len > 0 && val.data[val.len - 1] == '.') {
        val.len--;
    }

    value = rap_http_map_find(r, &map->map, &val);

    if (value == NULL) {
        value = map->default_value;
    }

    if (!value->valid) {
        cv = (rap_http_complex_value_t *) value->data;

        if (rap_http_complex_value(r, cv, &str) != RAP_OK) {
            return RAP_ERROR;
        }

        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->len = str.len;
        v->data = str.data;

    } else {
        *v = *value;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http map: \"%V\" \"%v\"", &val, v);

    return RAP_OK;
}


static void *
rap_http_map_create_conf(rap_conf_t *cf)
{
    rap_http_map_conf_t  *mcf;

    mcf = rap_palloc(cf->pool, sizeof(rap_http_map_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    mcf->hash_max_size = RAP_CONF_UNSET_UINT;
    mcf->hash_bucket_size = RAP_CONF_UNSET_UINT;

    return mcf;
}


static char *
rap_http_map_block(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_map_conf_t  *mcf = conf;

    char                              *rv;
    rap_str_t                         *value, name;
    rap_conf_t                         save;
    rap_pool_t                        *pool;
    rap_hash_init_t                    hash;
    rap_http_map_ctx_t                *map;
    rap_http_variable_t               *var;
    rap_http_map_conf_ctx_t            ctx;
    rap_http_compile_complex_value_t   ccv;

    if (mcf->hash_max_size == RAP_CONF_UNSET_UINT) {
        mcf->hash_max_size = 2048;
    }

    if (mcf->hash_bucket_size == RAP_CONF_UNSET_UINT) {
        mcf->hash_bucket_size = rap_cacheline_size;

    } else {
        mcf->hash_bucket_size = rap_align(mcf->hash_bucket_size,
                                          rap_cacheline_size);
    }

    map = rap_pcalloc(cf->pool, sizeof(rap_http_map_ctx_t));
    if (map == NULL) {
        return RAP_CONF_ERROR;
    }

    value = cf->args->elts;

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &map->value;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    name = value[2];

    if (name.data[0] != '$') {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return RAP_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = rap_http_add_variable(cf, &name, RAP_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return RAP_CONF_ERROR;
    }

    var->get_handler = rap_http_map_variable;
    var->data = (uintptr_t) map;

    pool = rap_create_pool(RAP_DEFAULT_POOL_SIZE, cf->log);
    if (pool == NULL) {
        return RAP_CONF_ERROR;
    }

    ctx.keys.pool = cf->pool;
    ctx.keys.temp_pool = pool;

    if (rap_hash_keys_array_init(&ctx.keys, RAP_HASH_LARGE) != RAP_OK) {
        rap_destroy_pool(pool);
        return RAP_CONF_ERROR;
    }

    ctx.values_hash = rap_pcalloc(pool, sizeof(rap_array_t) * ctx.keys.hsize);
    if (ctx.values_hash == NULL) {
        rap_destroy_pool(pool);
        return RAP_CONF_ERROR;
    }

#if (RAP_PCRE)
    if (rap_array_init(&ctx.regexes, cf->pool, 2, sizeof(rap_http_map_regex_t))
        != RAP_OK)
    {
        rap_destroy_pool(pool);
        return RAP_CONF_ERROR;
    }
#endif

    ctx.default_value = NULL;
    ctx.cf = &save;
    ctx.hostnames = 0;
    ctx.no_cacheable = 0;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = rap_http_map;
    cf->handler_conf = conf;

    rv = rap_conf_parse(cf, NULL);

    *cf = save;

    if (rv != RAP_CONF_OK) {
        rap_destroy_pool(pool);
        return rv;
    }

    if (ctx.no_cacheable) {
        var->flags |= RAP_HTTP_VAR_NOCACHEABLE;
    }

    map->default_value = ctx.default_value ? ctx.default_value:
                                             &rap_http_variable_null_value;

    map->hostnames = ctx.hostnames;

    hash.key = rap_hash_key_lc;
    hash.max_size = mcf->hash_max_size;
    hash.bucket_size = mcf->hash_bucket_size;
    hash.name = "map_hash";
    hash.pool = cf->pool;

    if (ctx.keys.keys.nelts) {
        hash.hash = &map->map.hash.hash;
        hash.temp_pool = NULL;

        if (rap_hash_init(&hash, ctx.keys.keys.elts, ctx.keys.keys.nelts)
            != RAP_OK)
        {
            rap_destroy_pool(pool);
            return RAP_CONF_ERROR;
        }
    }

    if (ctx.keys.dns_wc_head.nelts) {

        rap_qsort(ctx.keys.dns_wc_head.elts,
                  (size_t) ctx.keys.dns_wc_head.nelts,
                  sizeof(rap_hash_key_t), rap_http_map_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = pool;

        if (rap_hash_wildcard_init(&hash, ctx.keys.dns_wc_head.elts,
                                   ctx.keys.dns_wc_head.nelts)
            != RAP_OK)
        {
            rap_destroy_pool(pool);
            return RAP_CONF_ERROR;
        }

        map->map.hash.wc_head = (rap_hash_wildcard_t *) hash.hash;
    }

    if (ctx.keys.dns_wc_tail.nelts) {

        rap_qsort(ctx.keys.dns_wc_tail.elts,
                  (size_t) ctx.keys.dns_wc_tail.nelts,
                  sizeof(rap_hash_key_t), rap_http_map_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = pool;

        if (rap_hash_wildcard_init(&hash, ctx.keys.dns_wc_tail.elts,
                                   ctx.keys.dns_wc_tail.nelts)
            != RAP_OK)
        {
            rap_destroy_pool(pool);
            return RAP_CONF_ERROR;
        }

        map->map.hash.wc_tail = (rap_hash_wildcard_t *) hash.hash;
    }

#if (RAP_PCRE)

    if (ctx.regexes.nelts) {
        map->map.regex = ctx.regexes.elts;
        map->map.nregex = ctx.regexes.nelts;
    }

#endif

    rap_destroy_pool(pool);

    return rv;
}


static int rap_libc_cdecl
rap_http_map_cmp_dns_wildcards(const void *one, const void *two)
{
    rap_hash_key_t  *first, *second;

    first = (rap_hash_key_t *) one;
    second = (rap_hash_key_t *) two;

    return rap_dns_strcmp(first->key.data, second->key.data);
}


static char *
rap_http_map(rap_conf_t *cf, rap_command_t *dummy, void *conf)
{
    u_char                            *data;
    size_t                             len;
    rap_int_t                          rv;
    rap_str_t                         *value, v;
    rap_uint_t                         i, key;
    rap_http_map_conf_ctx_t           *ctx;
    rap_http_complex_value_t           cv, *cvp;
    rap_http_variable_value_t         *var, **vp;
    rap_http_compile_complex_value_t   ccv;

    ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts == 1
        && rap_strcmp(value[0].data, "hostnames") == 0)
    {
        ctx->hostnames = 1;
        return RAP_CONF_OK;
    }

    if (cf->args->nelts == 1
        && rap_strcmp(value[0].data, "volatile") == 0)
    {
        ctx->no_cacheable = 1;
        return RAP_CONF_OK;
    }

    if (cf->args->nelts != 2) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid number of the map parameters");
        return RAP_CONF_ERROR;
    }

    if (rap_strcmp(value[0].data, "include") == 0) {
        return rap_conf_include(cf, dummy, conf);
    }

    key = 0;

    for (i = 0; i < value[1].len; i++) {
        key = rap_hash(key, value[1].data[i]);
    }

    key %= ctx->keys.hsize;

    vp = ctx->values_hash[key].elts;

    if (vp) {
        for (i = 0; i < ctx->values_hash[key].nelts; i++) {

            if (vp[i]->valid) {
                data = vp[i]->data;
                len = vp[i]->len;

            } else {
                cvp = (rap_http_complex_value_t *) vp[i]->data;
                data = cvp->value.data;
                len = cvp->value.len;
            }

            if (value[1].len != len) {
                continue;
            }

            if (rap_strncmp(value[1].data, data, len) == 0) {
                var = vp[i];
                goto found;
            }
        }

    } else {
        if (rap_array_init(&ctx->values_hash[key], cf->pool, 4,
                           sizeof(rap_http_variable_value_t *))
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }
    }

    var = rap_palloc(ctx->keys.pool, sizeof(rap_http_variable_value_t));
    if (var == NULL) {
        return RAP_CONF_ERROR;
    }

    v.len = value[1].len;
    v.data = rap_pstrdup(ctx->keys.pool, &value[1]);
    if (v.data == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = ctx->cf;
    ccv.value = &v;
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths != NULL) {
        cvp = rap_palloc(ctx->keys.pool, sizeof(rap_http_complex_value_t));
        if (cvp == NULL) {
            return RAP_CONF_ERROR;
        }

        *cvp = cv;

        var->len = 0;
        var->data = (u_char *) cvp;
        var->valid = 0;

    } else {
        var->len = v.len;
        var->data = v.data;
        var->valid = 1;
    }

    var->no_cacheable = 0;
    var->not_found = 0;

    vp = rap_array_push(&ctx->values_hash[key]);
    if (vp == NULL) {
        return RAP_CONF_ERROR;
    }

    *vp = var;

found:

    if (rap_strcmp(value[0].data, "default") == 0) {

        if (ctx->default_value) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "duplicate default map parameter");
            return RAP_CONF_ERROR;
        }

        ctx->default_value = var;

        return RAP_CONF_OK;
    }

#if (RAP_PCRE)

    if (value[0].len && value[0].data[0] == '~') {
        rap_regex_compile_t    rc;
        rap_http_map_regex_t  *regex;
        u_char                 errstr[RAP_MAX_CONF_ERRSTR];

        regex = rap_array_push(&ctx->regexes);
        if (regex == NULL) {
            return RAP_CONF_ERROR;
        }

        value[0].len--;
        value[0].data++;

        rap_memzero(&rc, sizeof(rap_regex_compile_t));

        if (value[0].data[0] == '*') {
            value[0].len--;
            value[0].data++;
            rc.options = RAP_REGEX_CASELESS;
        }

        rc.pattern = value[0];
        rc.err.len = RAP_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        regex->regex = rap_http_regex_compile(ctx->cf, &rc);
        if (regex->regex == NULL) {
            return RAP_CONF_ERROR;
        }

        regex->value = var;

        return RAP_CONF_OK;
    }

#endif

    if (value[0].len && value[0].data[0] == '\\') {
        value[0].len--;
        value[0].data++;
    }

    rv = rap_hash_add_key(&ctx->keys, &value[0], var,
                          (ctx->hostnames) ? RAP_HASH_WILDCARD_KEY : 0);

    if (rv == RAP_OK) {
        return RAP_CONF_OK;
    }

    if (rv == RAP_DECLINED) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid hostname or wildcard \"%V\"", &value[0]);
    }

    if (rv == RAP_BUSY) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "conflicting parameter \"%V\"", &value[0]);
    }

    return RAP_CONF_ERROR;
}
