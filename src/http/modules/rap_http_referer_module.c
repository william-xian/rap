
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_REFERER_NO_URI_PART  ((void *) 4)


typedef struct {
    rap_hash_combined_t      hash;

#if (RAP_PCRE)
    rap_array_t             *regex;
    rap_array_t             *server_name_regex;
#endif

    rap_flag_t               no_referer;
    rap_flag_t               blocked_referer;
    rap_flag_t               server_names;

    rap_hash_keys_arrays_t  *keys;

    rap_uint_t               referer_hash_max_size;
    rap_uint_t               referer_hash_bucket_size;
} rap_http_referer_conf_t;


static rap_int_t rap_http_referer_add_variables(rap_conf_t *cf);
static void * rap_http_referer_create_conf(rap_conf_t *cf);
static char * rap_http_referer_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_http_valid_referers(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_http_add_referer(rap_conf_t *cf,
    rap_hash_keys_arrays_t *keys, rap_str_t *value, rap_str_t *uri);
static rap_int_t rap_http_add_regex_referer(rap_conf_t *cf,
    rap_http_referer_conf_t *rlcf, rap_str_t *name);
#if (RAP_PCRE)
static rap_int_t rap_http_add_regex_server_name(rap_conf_t *cf,
    rap_http_referer_conf_t *rlcf, rap_http_regex_t *regex);
#endif
static int rap_libc_cdecl rap_http_cmp_referer_wildcards(const void *one,
    const void *two);


static rap_command_t  rap_http_referer_commands[] = {

    { rap_string("valid_referers"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_http_valid_referers,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("referer_hash_max_size"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_referer_conf_t, referer_hash_max_size),
      NULL },

    { rap_string("referer_hash_bucket_size"),
      RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_referer_conf_t, referer_hash_bucket_size),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_referer_module_ctx = {
    rap_http_referer_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_referer_create_conf,          /* create location configuration */
    rap_http_referer_merge_conf            /* merge location configuration */
};


rap_module_t  rap_http_referer_module = {
    RAP_MODULE_V1,
    &rap_http_referer_module_ctx,          /* module context */
    rap_http_referer_commands,             /* module directives */
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


static rap_str_t  rap_http_invalid_referer_name = rap_string("invalid_referer");


static rap_int_t
rap_http_referer_variable(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    u_char                    *p, *ref, *last;
    size_t                     len;
    rap_str_t                 *uri;
    rap_uint_t                 i, key;
    rap_http_referer_conf_t   *rlcf;
    u_char                     buf[256];
#if (RAP_PCRE)
    rap_int_t                  rc;
    rap_str_t                  referer;
#endif

    rlcf = rap_http_get_module_loc_conf(r, rap_http_referer_module);

    if (rlcf->hash.hash.buckets == NULL
        && rlcf->hash.wc_head == NULL
        && rlcf->hash.wc_tail == NULL
#if (RAP_PCRE)
        && rlcf->regex == NULL
        && rlcf->server_name_regex == NULL
#endif
       )
    {
        goto valid;
    }

    if (r->headers_in.referer == NULL) {
        if (rlcf->no_referer) {
            goto valid;
        }

        goto invalid;
    }

    len = r->headers_in.referer->value.len;
    ref = r->headers_in.referer->value.data;

    if (len >= sizeof("http://i.ru") - 1) {
        last = ref + len;

        if (rap_strncasecmp(ref, (u_char *) "http://", 7) == 0) {
            ref += 7;
            len -= 7;
            goto valid_scheme;

        } else if (rap_strncasecmp(ref, (u_char *) "https://", 8) == 0) {
            ref += 8;
            len -= 8;
            goto valid_scheme;
        }
    }

    if (rlcf->blocked_referer) {
        goto valid;
    }

    goto invalid;

valid_scheme:

    i = 0;
    key = 0;

    for (p = ref; p < last; p++) {
        if (*p == '/' || *p == ':') {
            break;
        }

        if (i == 256) {
            goto invalid;
        }

        buf[i] = rap_tolower(*p);
        key = rap_hash(key, buf[i++]);
    }

    uri = rap_hash_find_combined(&rlcf->hash, key, buf, p - ref);

    if (uri) {
        goto uri;
    }

#if (RAP_PCRE)

    if (rlcf->server_name_regex) {
        referer.len = p - ref;
        referer.data = buf;

        rc = rap_regex_exec_array(rlcf->server_name_regex, &referer,
                                  r->connection->log);

        if (rc == RAP_OK) {
            goto valid;
        }

        if (rc == RAP_ERROR) {
            return rc;
        }

        /* RAP_DECLINED */
    }

    if (rlcf->regex) {
        referer.len = len;
        referer.data = ref;

        rc = rap_regex_exec_array(rlcf->regex, &referer, r->connection->log);

        if (rc == RAP_OK) {
            goto valid;
        }

        if (rc == RAP_ERROR) {
            return rc;
        }

        /* RAP_DECLINED */
    }

#endif

invalid:

    *v = rap_http_variable_true_value;

    return RAP_OK;

uri:

    for ( /* void */ ; p < last; p++) {
        if (*p == '/') {
            break;
        }
    }

    len = last - p;

    if (uri == RAP_HTTP_REFERER_NO_URI_PART) {
        goto valid;
    }

    if (len < uri->len || rap_strncmp(uri->data, p, uri->len) != 0) {
        goto invalid;
    }

valid:

    *v = rap_http_variable_null_value;

    return RAP_OK;
}


static rap_int_t
rap_http_referer_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var;

    var = rap_http_add_variable(cf, &rap_http_invalid_referer_name,
                                RAP_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return RAP_ERROR;
    }

    var->get_handler = rap_http_referer_variable;

    return RAP_OK;
}


static void *
rap_http_referer_create_conf(rap_conf_t *cf)
{
    rap_http_referer_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_referer_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->hash = { NULL };
     *     conf->server_names = 0;
     *     conf->keys = NULL;
     */

#if (RAP_PCRE)
    conf->regex = RAP_CONF_UNSET_PTR;
    conf->server_name_regex = RAP_CONF_UNSET_PTR;
#endif

    conf->no_referer = RAP_CONF_UNSET;
    conf->blocked_referer = RAP_CONF_UNSET;
    conf->referer_hash_max_size = RAP_CONF_UNSET_UINT;
    conf->referer_hash_bucket_size = RAP_CONF_UNSET_UINT;

    return conf;
}


static char *
rap_http_referer_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_referer_conf_t *prev = parent;
    rap_http_referer_conf_t *conf = child;

    rap_uint_t                 n;
    rap_hash_init_t            hash;
    rap_http_server_name_t    *sn;
    rap_http_core_srv_conf_t  *cscf;

    if (conf->keys == NULL) {
        conf->hash = prev->hash;

#if (RAP_PCRE)
        rap_conf_merge_ptr_value(conf->regex, prev->regex, NULL);
        rap_conf_merge_ptr_value(conf->server_name_regex,
                                 prev->server_name_regex, NULL);
#endif
        rap_conf_merge_value(conf->no_referer, prev->no_referer, 0);
        rap_conf_merge_value(conf->blocked_referer, prev->blocked_referer, 0);
        rap_conf_merge_uint_value(conf->referer_hash_max_size,
                                  prev->referer_hash_max_size, 2048);
        rap_conf_merge_uint_value(conf->referer_hash_bucket_size,
                                  prev->referer_hash_bucket_size, 64);

        return RAP_CONF_OK;
    }

    if (conf->server_names == 1) {
        cscf = rap_http_conf_get_module_srv_conf(cf, rap_http_core_module);

        sn = cscf->server_names.elts;
        for (n = 0; n < cscf->server_names.nelts; n++) {

#if (RAP_PCRE)
            if (sn[n].regex) {

                if (rap_http_add_regex_server_name(cf, conf, sn[n].regex)
                    != RAP_OK)
                {
                    return RAP_CONF_ERROR;
                }

                continue;
            }
#endif

            if (rap_http_add_referer(cf, conf->keys, &sn[n].name, NULL)
                != RAP_OK)
            {
                return RAP_CONF_ERROR;
            }
        }
    }

    if ((conf->no_referer == 1 || conf->blocked_referer == 1)
        && conf->keys->keys.nelts == 0
        && conf->keys->dns_wc_head.nelts == 0
        && conf->keys->dns_wc_tail.nelts == 0)
    {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "the \"none\" or \"blocked\" referers are specified "
                      "in the \"valid_referers\" directive "
                      "without any valid referer");
        return RAP_CONF_ERROR;
    }

    rap_conf_merge_uint_value(conf->referer_hash_max_size,
                              prev->referer_hash_max_size, 2048);
    rap_conf_merge_uint_value(conf->referer_hash_bucket_size,
                              prev->referer_hash_bucket_size, 64);
    conf->referer_hash_bucket_size = rap_align(conf->referer_hash_bucket_size,
                                               rap_cacheline_size);

    hash.key = rap_hash_key_lc;
    hash.max_size = conf->referer_hash_max_size;
    hash.bucket_size = conf->referer_hash_bucket_size;
    hash.name = "referer_hash";
    hash.pool = cf->pool;

    if (conf->keys->keys.nelts) {
        hash.hash = &conf->hash.hash;
        hash.temp_pool = NULL;

        if (rap_hash_init(&hash, conf->keys->keys.elts, conf->keys->keys.nelts)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }
    }

    if (conf->keys->dns_wc_head.nelts) {

        rap_qsort(conf->keys->dns_wc_head.elts,
                  (size_t) conf->keys->dns_wc_head.nelts,
                  sizeof(rap_hash_key_t),
                  rap_http_cmp_referer_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (rap_hash_wildcard_init(&hash, conf->keys->dns_wc_head.elts,
                                   conf->keys->dns_wc_head.nelts)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }

        conf->hash.wc_head = (rap_hash_wildcard_t *) hash.hash;
    }

    if (conf->keys->dns_wc_tail.nelts) {

        rap_qsort(conf->keys->dns_wc_tail.elts,
                  (size_t) conf->keys->dns_wc_tail.nelts,
                  sizeof(rap_hash_key_t),
                  rap_http_cmp_referer_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (rap_hash_wildcard_init(&hash, conf->keys->dns_wc_tail.elts,
                                   conf->keys->dns_wc_tail.nelts)
            != RAP_OK)
        {
            return RAP_CONF_ERROR;
        }

        conf->hash.wc_tail = (rap_hash_wildcard_t *) hash.hash;
    }

#if (RAP_PCRE)
    rap_conf_merge_ptr_value(conf->regex, prev->regex, NULL);
    rap_conf_merge_ptr_value(conf->server_name_regex, prev->server_name_regex,
                             NULL);
#endif

    if (conf->no_referer == RAP_CONF_UNSET) {
        conf->no_referer = 0;
    }

    if (conf->blocked_referer == RAP_CONF_UNSET) {
        conf->blocked_referer = 0;
    }

    conf->keys = NULL;

    return RAP_CONF_OK;
}


static char *
rap_http_valid_referers(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_referer_conf_t  *rlcf = conf;

    u_char      *p;
    rap_str_t   *value, uri;
    rap_uint_t   i;

    if (rlcf->keys == NULL) {
        rlcf->keys = rap_pcalloc(cf->temp_pool, sizeof(rap_hash_keys_arrays_t));
        if (rlcf->keys == NULL) {
            return RAP_CONF_ERROR;
        }

        rlcf->keys->pool = cf->pool;
        rlcf->keys->temp_pool = cf->pool;

        if (rap_hash_keys_array_init(rlcf->keys, RAP_HASH_SMALL) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid referer \"%V\"", &value[i]);
            return RAP_CONF_ERROR;
        }

        if (rap_strcmp(value[i].data, "none") == 0) {
            rlcf->no_referer = 1;
            continue;
        }

        if (rap_strcmp(value[i].data, "blocked") == 0) {
            rlcf->blocked_referer = 1;
            continue;
        }

        if (rap_strcmp(value[i].data, "server_names") == 0) {
            rlcf->server_names = 1;
            continue;
        }

        if (value[i].data[0] == '~') {
            if (rap_http_add_regex_referer(cf, rlcf, &value[i]) != RAP_OK) {
                return RAP_CONF_ERROR;
            }

            continue;
        }

        rap_str_null(&uri);

        p = (u_char *) rap_strchr(value[i].data, '/');

        if (p) {
            uri.len = (value[i].data + value[i].len) - p;
            uri.data = p;
            value[i].len = p - value[i].data;
        }

        if (rap_http_add_referer(cf, rlcf->keys, &value[i], &uri) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_add_referer(rap_conf_t *cf, rap_hash_keys_arrays_t *keys,
    rap_str_t *value, rap_str_t *uri)
{
    rap_int_t   rc;
    rap_str_t  *u;

    if (uri == NULL || uri->len == 0) {
        u = RAP_HTTP_REFERER_NO_URI_PART;

    } else {
        u = rap_palloc(cf->pool, sizeof(rap_str_t));
        if (u == NULL) {
            return RAP_ERROR;
        }

        *u = *uri;
    }

    rc = rap_hash_add_key(keys, value, u, RAP_HASH_WILDCARD_KEY);

    if (rc == RAP_OK) {
        return RAP_OK;
    }

    if (rc == RAP_DECLINED) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid hostname or wildcard \"%V\"", value);
    }

    if (rc == RAP_BUSY) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "conflicting parameter \"%V\"", value);
    }

    return RAP_ERROR;
}


static rap_int_t
rap_http_add_regex_referer(rap_conf_t *cf, rap_http_referer_conf_t *rlcf,
    rap_str_t *name)
{
#if (RAP_PCRE)
    rap_regex_elt_t      *re;
    rap_regex_compile_t   rc;
    u_char                errstr[RAP_MAX_CONF_ERRSTR];

    if (name->len == 1) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "empty regex in \"%V\"", name);
        return RAP_ERROR;
    }

    if (rlcf->regex == RAP_CONF_UNSET_PTR) {
        rlcf->regex = rap_array_create(cf->pool, 2, sizeof(rap_regex_elt_t));
        if (rlcf->regex == NULL) {
            return RAP_ERROR;
        }
    }

    re = rap_array_push(rlcf->regex);
    if (re == NULL) {
        return RAP_ERROR;
    }

    name->len--;
    name->data++;

    rap_memzero(&rc, sizeof(rap_regex_compile_t));

    rc.pattern = *name;
    rc.pool = cf->pool;
    rc.options = RAP_REGEX_CASELESS;
    rc.err.len = RAP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (rap_regex_compile(&rc) != RAP_OK) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "%V", &rc.err);
        return RAP_ERROR;
    }

    re->regex = rc.regex;
    re->name = name->data;

    return RAP_OK;

#else

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "the using of the regex \"%V\" requires PCRE library",
                       name);

    return RAP_ERROR;

#endif
}


#if (RAP_PCRE)

static rap_int_t
rap_http_add_regex_server_name(rap_conf_t *cf, rap_http_referer_conf_t *rlcf,
    rap_http_regex_t *regex)
{
    rap_regex_elt_t  *re;

    if (rlcf->server_name_regex == RAP_CONF_UNSET_PTR) {
        rlcf->server_name_regex = rap_array_create(cf->pool, 2,
                                                   sizeof(rap_regex_elt_t));
        if (rlcf->server_name_regex == NULL) {
            return RAP_ERROR;
        }
    }

    re = rap_array_push(rlcf->server_name_regex);
    if (re == NULL) {
        return RAP_ERROR;
    }

    re->regex = regex->regex;
    re->name = regex->name.data;

    return RAP_OK;
}

#endif


static int rap_libc_cdecl
rap_http_cmp_referer_wildcards(const void *one, const void *two)
{
    rap_hash_key_t  *first, *second;

    first = (rap_hash_key_t *) one;
    second = (rap_hash_key_t *) two;

    return rap_dns_strcmp(first->key.data, second->key.data);
}
