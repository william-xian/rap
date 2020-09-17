
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_uint_t                  hash_max_size;
    rp_uint_t                  hash_bucket_size;
} rp_http_map_conf_t;


typedef struct {
    rp_hash_keys_arrays_t      keys;

    rp_array_t                *values_hash;
#if (RP_PCRE)
    rp_array_t                 regexes;
#endif

    rp_http_variable_value_t  *default_value;
    rp_conf_t                 *cf;
    unsigned                    hostnames:1;
    unsigned                    no_cacheable:1;
} rp_http_map_conf_ctx_t;


typedef struct {
    rp_http_map_t              map;
    rp_http_complex_value_t    value;
    rp_http_variable_value_t  *default_value;
    rp_uint_t                  hostnames;      /* unsigned  hostnames:1 */
} rp_http_map_ctx_t;


static int rp_libc_cdecl rp_http_map_cmp_dns_wildcards(const void *one,
    const void *two);
static void *rp_http_map_create_conf(rp_conf_t *cf);
static char *rp_http_map_block(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static char *rp_http_map(rp_conf_t *cf, rp_command_t *dummy, void *conf);


static rp_command_t  rp_http_map_commands[] = {

    { rp_string("map"),
      RP_HTTP_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_TAKE2,
      rp_http_map_block,
      RP_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { rp_string("map_hash_max_size"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_map_conf_t, hash_max_size),
      NULL },

    { rp_string("map_hash_bucket_size"),
      RP_HTTP_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_MAIN_CONF_OFFSET,
      offsetof(rp_http_map_conf_t, hash_bucket_size),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_map_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rp_http_map_create_conf,              /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_map_module = {
    RP_MODULE_V1,
    &rp_http_map_module_ctx,              /* module context */
    rp_http_map_commands,                 /* module directives */
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
rp_http_map_variable(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    rp_http_map_ctx_t  *map = (rp_http_map_ctx_t *) data;

    rp_str_t                   val, str;
    rp_http_complex_value_t   *cv;
    rp_http_variable_value_t  *value;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http map started");

    if (rp_http_complex_value(r, &map->value, &val) != RP_OK) {
        return RP_ERROR;
    }

    if (map->hostnames && val.len > 0 && val.data[val.len - 1] == '.') {
        val.len--;
    }

    value = rp_http_map_find(r, &map->map, &val);

    if (value == NULL) {
        value = map->default_value;
    }

    if (!value->valid) {
        cv = (rp_http_complex_value_t *) value->data;

        if (rp_http_complex_value(r, cv, &str) != RP_OK) {
            return RP_ERROR;
        }

        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->len = str.len;
        v->data = str.data;

    } else {
        *v = *value;
    }

    rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http map: \"%V\" \"%v\"", &val, v);

    return RP_OK;
}


static void *
rp_http_map_create_conf(rp_conf_t *cf)
{
    rp_http_map_conf_t  *mcf;

    mcf = rp_palloc(cf->pool, sizeof(rp_http_map_conf_t));
    if (mcf == NULL) {
        return NULL;
    }

    mcf->hash_max_size = RP_CONF_UNSET_UINT;
    mcf->hash_bucket_size = RP_CONF_UNSET_UINT;

    return mcf;
}


static char *
rp_http_map_block(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_map_conf_t  *mcf = conf;

    char                              *rv;
    rp_str_t                         *value, name;
    rp_conf_t                         save;
    rp_pool_t                        *pool;
    rp_hash_init_t                    hash;
    rp_http_map_ctx_t                *map;
    rp_http_variable_t               *var;
    rp_http_map_conf_ctx_t            ctx;
    rp_http_compile_complex_value_t   ccv;

    if (mcf->hash_max_size == RP_CONF_UNSET_UINT) {
        mcf->hash_max_size = 2048;
    }

    if (mcf->hash_bucket_size == RP_CONF_UNSET_UINT) {
        mcf->hash_bucket_size = rp_cacheline_size;

    } else {
        mcf->hash_bucket_size = rp_align(mcf->hash_bucket_size,
                                          rp_cacheline_size);
    }

    map = rp_pcalloc(cf->pool, sizeof(rp_http_map_ctx_t));
    if (map == NULL) {
        return RP_CONF_ERROR;
    }

    value = cf->args->elts;

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &map->value;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    name = value[2];

    if (name.data[0] != '$') {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return RP_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = rp_http_add_variable(cf, &name, RP_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return RP_CONF_ERROR;
    }

    var->get_handler = rp_http_map_variable;
    var->data = (uintptr_t) map;

    pool = rp_create_pool(RP_DEFAULT_POOL_SIZE, cf->log);
    if (pool == NULL) {
        return RP_CONF_ERROR;
    }

    ctx.keys.pool = cf->pool;
    ctx.keys.temp_pool = pool;

    if (rp_hash_keys_array_init(&ctx.keys, RP_HASH_LARGE) != RP_OK) {
        rp_destroy_pool(pool);
        return RP_CONF_ERROR;
    }

    ctx.values_hash = rp_pcalloc(pool, sizeof(rp_array_t) * ctx.keys.hsize);
    if (ctx.values_hash == NULL) {
        rp_destroy_pool(pool);
        return RP_CONF_ERROR;
    }

#if (RP_PCRE)
    if (rp_array_init(&ctx.regexes, cf->pool, 2, sizeof(rp_http_map_regex_t))
        != RP_OK)
    {
        rp_destroy_pool(pool);
        return RP_CONF_ERROR;
    }
#endif

    ctx.default_value = NULL;
    ctx.cf = &save;
    ctx.hostnames = 0;
    ctx.no_cacheable = 0;

    save = *cf;
    cf->pool = pool;
    cf->ctx = &ctx;
    cf->handler = rp_http_map;
    cf->handler_conf = conf;

    rv = rp_conf_parse(cf, NULL);

    *cf = save;

    if (rv != RP_CONF_OK) {
        rp_destroy_pool(pool);
        return rv;
    }

    if (ctx.no_cacheable) {
        var->flags |= RP_HTTP_VAR_NOCACHEABLE;
    }

    map->default_value = ctx.default_value ? ctx.default_value:
                                             &rp_http_variable_null_value;

    map->hostnames = ctx.hostnames;

    hash.key = rp_hash_key_lc;
    hash.max_size = mcf->hash_max_size;
    hash.bucket_size = mcf->hash_bucket_size;
    hash.name = "map_hash";
    hash.pool = cf->pool;

    if (ctx.keys.keys.nelts) {
        hash.hash = &map->map.hash.hash;
        hash.temp_pool = NULL;

        if (rp_hash_init(&hash, ctx.keys.keys.elts, ctx.keys.keys.nelts)
            != RP_OK)
        {
            rp_destroy_pool(pool);
            return RP_CONF_ERROR;
        }
    }

    if (ctx.keys.dns_wc_head.nelts) {

        rp_qsort(ctx.keys.dns_wc_head.elts,
                  (size_t) ctx.keys.dns_wc_head.nelts,
                  sizeof(rp_hash_key_t), rp_http_map_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = pool;

        if (rp_hash_wildcard_init(&hash, ctx.keys.dns_wc_head.elts,
                                   ctx.keys.dns_wc_head.nelts)
            != RP_OK)
        {
            rp_destroy_pool(pool);
            return RP_CONF_ERROR;
        }

        map->map.hash.wc_head = (rp_hash_wildcard_t *) hash.hash;
    }

    if (ctx.keys.dns_wc_tail.nelts) {

        rp_qsort(ctx.keys.dns_wc_tail.elts,
                  (size_t) ctx.keys.dns_wc_tail.nelts,
                  sizeof(rp_hash_key_t), rp_http_map_cmp_dns_wildcards);

        hash.hash = NULL;
        hash.temp_pool = pool;

        if (rp_hash_wildcard_init(&hash, ctx.keys.dns_wc_tail.elts,
                                   ctx.keys.dns_wc_tail.nelts)
            != RP_OK)
        {
            rp_destroy_pool(pool);
            return RP_CONF_ERROR;
        }

        map->map.hash.wc_tail = (rp_hash_wildcard_t *) hash.hash;
    }

#if (RP_PCRE)

    if (ctx.regexes.nelts) {
        map->map.regex = ctx.regexes.elts;
        map->map.nregex = ctx.regexes.nelts;
    }

#endif

    rp_destroy_pool(pool);

    return rv;
}


static int rp_libc_cdecl
rp_http_map_cmp_dns_wildcards(const void *one, const void *two)
{
    rp_hash_key_t  *first, *second;

    first = (rp_hash_key_t *) one;
    second = (rp_hash_key_t *) two;

    return rp_dns_strcmp(first->key.data, second->key.data);
}


static char *
rp_http_map(rp_conf_t *cf, rp_command_t *dummy, void *conf)
{
    u_char                            *data;
    size_t                             len;
    rp_int_t                          rv;
    rp_str_t                         *value, v;
    rp_uint_t                         i, key;
    rp_http_map_conf_ctx_t           *ctx;
    rp_http_complex_value_t           cv, *cvp;
    rp_http_variable_value_t         *var, **vp;
    rp_http_compile_complex_value_t   ccv;

    ctx = cf->ctx;

    value = cf->args->elts;

    if (cf->args->nelts == 1
        && rp_strcmp(value[0].data, "hostnames") == 0)
    {
        ctx->hostnames = 1;
        return RP_CONF_OK;
    }

    if (cf->args->nelts == 1
        && rp_strcmp(value[0].data, "volatile") == 0)
    {
        ctx->no_cacheable = 1;
        return RP_CONF_OK;
    }

    if (cf->args->nelts != 2) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid number of the map parameters");
        return RP_CONF_ERROR;
    }

    if (rp_strcmp(value[0].data, "include") == 0) {
        return rp_conf_include(cf, dummy, conf);
    }

    key = 0;

    for (i = 0; i < value[1].len; i++) {
        key = rp_hash(key, value[1].data[i]);
    }

    key %= ctx->keys.hsize;

    vp = ctx->values_hash[key].elts;

    if (vp) {
        for (i = 0; i < ctx->values_hash[key].nelts; i++) {

            if (vp[i]->valid) {
                data = vp[i]->data;
                len = vp[i]->len;

            } else {
                cvp = (rp_http_complex_value_t *) vp[i]->data;
                data = cvp->value.data;
                len = cvp->value.len;
            }

            if (value[1].len != len) {
                continue;
            }

            if (rp_strncmp(value[1].data, data, len) == 0) {
                var = vp[i];
                goto found;
            }
        }

    } else {
        if (rp_array_init(&ctx->values_hash[key], cf->pool, 4,
                           sizeof(rp_http_variable_value_t *))
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }
    }

    var = rp_palloc(ctx->keys.pool, sizeof(rp_http_variable_value_t));
    if (var == NULL) {
        return RP_CONF_ERROR;
    }

    v.len = value[1].len;
    v.data = rp_pstrdup(ctx->keys.pool, &value[1]);
    if (v.data == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = ctx->cf;
    ccv.value = &v;
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths != NULL) {
        cvp = rp_palloc(ctx->keys.pool, sizeof(rp_http_complex_value_t));
        if (cvp == NULL) {
            return RP_CONF_ERROR;
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

    vp = rp_array_push(&ctx->values_hash[key]);
    if (vp == NULL) {
        return RP_CONF_ERROR;
    }

    *vp = var;

found:

    if (rp_strcmp(value[0].data, "default") == 0) {

        if (ctx->default_value) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "duplicate default map parameter");
            return RP_CONF_ERROR;
        }

        ctx->default_value = var;

        return RP_CONF_OK;
    }

#if (RP_PCRE)

    if (value[0].len && value[0].data[0] == '~') {
        rp_regex_compile_t    rc;
        rp_http_map_regex_t  *regex;
        u_char                 errstr[RP_MAX_CONF_ERRSTR];

        regex = rp_array_push(&ctx->regexes);
        if (regex == NULL) {
            return RP_CONF_ERROR;
        }

        value[0].len--;
        value[0].data++;

        rp_memzero(&rc, sizeof(rp_regex_compile_t));

        if (value[0].data[0] == '*') {
            value[0].len--;
            value[0].data++;
            rc.options = RP_REGEX_CASELESS;
        }

        rc.pattern = value[0];
        rc.err.len = RP_MAX_CONF_ERRSTR;
        rc.err.data = errstr;

        regex->regex = rp_http_regex_compile(ctx->cf, &rc);
        if (regex->regex == NULL) {
            return RP_CONF_ERROR;
        }

        regex->value = var;

        return RP_CONF_OK;
    }

#endif

    if (value[0].len && value[0].data[0] == '\\') {
        value[0].len--;
        value[0].data++;
    }

    rv = rp_hash_add_key(&ctx->keys, &value[0], var,
                          (ctx->hostnames) ? RP_HASH_WILDCARD_KEY : 0);

    if (rv == RP_OK) {
        return RP_CONF_OK;
    }

    if (rv == RP_DECLINED) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid hostname or wildcard \"%V\"", &value[0]);
    }

    if (rv == RP_BUSY) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "conflicting parameter \"%V\"", &value[0]);
    }

    return RP_CONF_ERROR;
}
