
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_REFERER_NO_URI_PART  ((void *) 4)


typedef struct {
    rp_hash_combined_t      hash;

#if (RP_PCRE)
    rp_array_t             *regex;
    rp_array_t             *server_name_regex;
#endif

    rp_flag_t               no_referer;
    rp_flag_t               blocked_referer;
    rp_flag_t               server_names;

    rp_hash_keys_arrays_t  *keys;

    rp_uint_t               referer_hash_max_size;
    rp_uint_t               referer_hash_bucket_size;
} rp_http_referer_conf_t;


static rp_int_t rp_http_referer_add_variables(rp_conf_t *cf);
static void * rp_http_referer_create_conf(rp_conf_t *cf);
static char * rp_http_referer_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_http_valid_referers(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_http_add_referer(rp_conf_t *cf,
    rp_hash_keys_arrays_t *keys, rp_str_t *value, rp_str_t *uri);
static rp_int_t rp_http_add_regex_referer(rp_conf_t *cf,
    rp_http_referer_conf_t *rlcf, rp_str_t *name);
#if (RP_PCRE)
static rp_int_t rp_http_add_regex_server_name(rp_conf_t *cf,
    rp_http_referer_conf_t *rlcf, rp_http_regex_t *regex);
#endif
static int rp_libc_cdecl rp_http_cmp_referer_wildcards(const void *one,
    const void *two);


static rp_command_t  rp_http_referer_commands[] = {

    { rp_string("valid_referers"),
      RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_http_valid_referers,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("referer_hash_max_size"),
      RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_referer_conf_t, referer_hash_max_size),
      NULL },

    { rp_string("referer_hash_bucket_size"),
      RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_referer_conf_t, referer_hash_bucket_size),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_referer_module_ctx = {
    rp_http_referer_add_variables,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_referer_create_conf,          /* create location configuration */
    rp_http_referer_merge_conf            /* merge location configuration */
};


rp_module_t  rp_http_referer_module = {
    RP_MODULE_V1,
    &rp_http_referer_module_ctx,          /* module context */
    rp_http_referer_commands,             /* module directives */
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


static rp_str_t  rp_http_invalid_referer_name = rp_string("invalid_referer");


static rp_int_t
rp_http_referer_variable(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    u_char                    *p, *ref, *last;
    size_t                     len;
    rp_str_t                 *uri;
    rp_uint_t                 i, key;
    rp_http_referer_conf_t   *rlcf;
    u_char                     buf[256];
#if (RP_PCRE)
    rp_int_t                  rc;
    rp_str_t                  referer;
#endif

    rlcf = rp_http_get_module_loc_conf(r, rp_http_referer_module);

    if (rlcf->hash.hash.buckets == NULL
        && rlcf->hash.wc_head == NULL
        && rlcf->hash.wc_tail == NULL
#if (RP_PCRE)
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

        if (rp_strncasecmp(ref, (u_char *) "http://", 7) == 0) {
            ref += 7;
            len -= 7;
            goto valid_scheme;

        } else if (rp_strncasecmp(ref, (u_char *) "https://", 8) == 0) {
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

        buf[i] = rp_tolower(*p);
        key = rp_hash(key, buf[i++]);
    }

    uri = rp_hash_find_combined(&rlcf->hash, key, buf, p - ref);

    if (uri) {
        goto uri;
    }

#if (RP_PCRE)

    if (rlcf->server_name_regex) {
        referer.len = p - ref;
        referer.data = buf;

        rc = rp_regex_exec_array(rlcf->server_name_regex, &referer,
                                  r->connection->log);

        if (rc == RP_OK) {
            goto valid;
        }

        if (rc == RP_ERROR) {
            return rc;
        }

        /* RP_DECLINED */
    }

    if (rlcf->regex) {
        referer.len = len;
        referer.data = ref;

        rc = rp_regex_exec_array(rlcf->regex, &referer, r->connection->log);

        if (rc == RP_OK) {
            goto valid;
        }

        if (rc == RP_ERROR) {
            return rc;
        }

        /* RP_DECLINED */
    }

#endif

invalid:

    *v = rp_http_variable_true_value;

    return RP_OK;

uri:

    for ( /* void */ ; p < last; p++) {
        if (*p == '/') {
            break;
        }
    }

    len = last - p;

    if (uri == RP_HTTP_REFERER_NO_URI_PART) {
        goto valid;
    }

    if (len < uri->len || rp_strncmp(uri->data, p, uri->len) != 0) {
        goto invalid;
    }

valid:

    *v = rp_http_variable_null_value;

    return RP_OK;
}


static rp_int_t
rp_http_referer_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var;

    var = rp_http_add_variable(cf, &rp_http_invalid_referer_name,
                                RP_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return RP_ERROR;
    }

    var->get_handler = rp_http_referer_variable;

    return RP_OK;
}


static void *
rp_http_referer_create_conf(rp_conf_t *cf)
{
    rp_http_referer_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_referer_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->hash = { NULL };
     *     conf->server_names = 0;
     *     conf->keys = NULL;
     */

#if (RP_PCRE)
    conf->regex = RP_CONF_UNSET_PTR;
    conf->server_name_regex = RP_CONF_UNSET_PTR;
#endif

    conf->no_referer = RP_CONF_UNSET;
    conf->blocked_referer = RP_CONF_UNSET;
    conf->referer_hash_max_size = RP_CONF_UNSET_UINT;
    conf->referer_hash_bucket_size = RP_CONF_UNSET_UINT;

    return conf;
}


static char *
rp_http_referer_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_referer_conf_t *prev = parent;
    rp_http_referer_conf_t *conf = child;

    rp_uint_t                 n;
    rp_hash_init_t            hash;
    rp_http_server_name_t    *sn;
    rp_http_core_srv_conf_t  *cscf;

    if (conf->keys == NULL) {
        conf->hash = prev->hash;

#if (RP_PCRE)
        rp_conf_merge_ptr_value(conf->regex, prev->regex, NULL);
        rp_conf_merge_ptr_value(conf->server_name_regex,
                                 prev->server_name_regex, NULL);
#endif
        rp_conf_merge_value(conf->no_referer, prev->no_referer, 0);
        rp_conf_merge_value(conf->blocked_referer, prev->blocked_referer, 0);
        rp_conf_merge_uint_value(conf->referer_hash_max_size,
                                  prev->referer_hash_max_size, 2048);
        rp_conf_merge_uint_value(conf->referer_hash_bucket_size,
                                  prev->referer_hash_bucket_size, 64);

        return RP_CONF_OK;
    }

    if (conf->server_names == 1) {
        cscf = rp_http_conf_get_module_srv_conf(cf, rp_http_core_module);

        sn = cscf->server_names.elts;
        for (n = 0; n < cscf->server_names.nelts; n++) {

#if (RP_PCRE)
            if (sn[n].regex) {

                if (rp_http_add_regex_server_name(cf, conf, sn[n].regex)
                    != RP_OK)
                {
                    return RP_CONF_ERROR;
                }

                continue;
            }
#endif

            if (rp_http_add_referer(cf, conf->keys, &sn[n].name, NULL)
                != RP_OK)
            {
                return RP_CONF_ERROR;
            }
        }
    }

    if ((conf->no_referer == 1 || conf->blocked_referer == 1)
        && conf->keys->keys.nelts == 0
        && conf->keys->dns_wc_head.nelts == 0
        && conf->keys->dns_wc_tail.nelts == 0)
    {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "the \"none\" or \"blocked\" referers are specified "
                      "in the \"valid_referers\" directive "
                      "without any valid referer");
        return RP_CONF_ERROR;
    }

    rp_conf_merge_uint_value(conf->referer_hash_max_size,
                              prev->referer_hash_max_size, 2048);
    rp_conf_merge_uint_value(conf->referer_hash_bucket_size,
                              prev->referer_hash_bucket_size, 64);
    conf->referer_hash_bucket_size = rp_align(conf->referer_hash_bucket_size,
                                               rp_cacheline_size);

    hash.key = rp_hash_key_lc;
    hash.max_size = conf->referer_hash_max_size;
    hash.bucket_size = conf->referer_hash_bucket_size;
    hash.name = "referer_hash";
    hash.pool = cf->pool;

    if (conf->keys->keys.nelts) {
        hash.hash = &conf->hash.hash;
        hash.temp_pool = NULL;

        if (rp_hash_init(&hash, conf->keys->keys.elts, conf->keys->keys.nelts)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }
    }

    if (conf->keys->dns_wc_head.nelts) {

        rp_qsort(conf->keys->dns_wc_head.elts,
                  (size_t) conf->keys->dns_wc_head.nelts,
                  sizeof(rp_hash_key_t),
                  rp_http_cmp_referer_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (rp_hash_wildcard_init(&hash, conf->keys->dns_wc_head.elts,
                                   conf->keys->dns_wc_head.nelts)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }

        conf->hash.wc_head = (rp_hash_wildcard_t *) hash.hash;
    }

    if (conf->keys->dns_wc_tail.nelts) {

        rp_qsort(conf->keys->dns_wc_tail.elts,
                  (size_t) conf->keys->dns_wc_tail.nelts,
                  sizeof(rp_hash_key_t),
                  rp_http_cmp_referer_wildcards);

        hash.hash = NULL;
        hash.temp_pool = cf->temp_pool;

        if (rp_hash_wildcard_init(&hash, conf->keys->dns_wc_tail.elts,
                                   conf->keys->dns_wc_tail.nelts)
            != RP_OK)
        {
            return RP_CONF_ERROR;
        }

        conf->hash.wc_tail = (rp_hash_wildcard_t *) hash.hash;
    }

#if (RP_PCRE)
    rp_conf_merge_ptr_value(conf->regex, prev->regex, NULL);
    rp_conf_merge_ptr_value(conf->server_name_regex, prev->server_name_regex,
                             NULL);
#endif

    if (conf->no_referer == RP_CONF_UNSET) {
        conf->no_referer = 0;
    }

    if (conf->blocked_referer == RP_CONF_UNSET) {
        conf->blocked_referer = 0;
    }

    conf->keys = NULL;

    return RP_CONF_OK;
}


static char *
rp_http_valid_referers(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_referer_conf_t  *rlcf = conf;

    u_char      *p;
    rp_str_t   *value, uri;
    rp_uint_t   i;

    if (rlcf->keys == NULL) {
        rlcf->keys = rp_pcalloc(cf->temp_pool, sizeof(rp_hash_keys_arrays_t));
        if (rlcf->keys == NULL) {
            return RP_CONF_ERROR;
        }

        rlcf->keys->pool = cf->pool;
        rlcf->keys->temp_pool = cf->pool;

        if (rp_hash_keys_array_init(rlcf->keys, RP_HASH_SMALL) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        if (value[i].len == 0) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid referer \"%V\"", &value[i]);
            return RP_CONF_ERROR;
        }

        if (rp_strcmp(value[i].data, "none") == 0) {
            rlcf->no_referer = 1;
            continue;
        }

        if (rp_strcmp(value[i].data, "blocked") == 0) {
            rlcf->blocked_referer = 1;
            continue;
        }

        if (rp_strcmp(value[i].data, "server_names") == 0) {
            rlcf->server_names = 1;
            continue;
        }

        if (value[i].data[0] == '~') {
            if (rp_http_add_regex_referer(cf, rlcf, &value[i]) != RP_OK) {
                return RP_CONF_ERROR;
            }

            continue;
        }

        rp_str_null(&uri);

        p = (u_char *) rp_strchr(value[i].data, '/');

        if (p) {
            uri.len = (value[i].data + value[i].len) - p;
            uri.data = p;
            value[i].len = p - value[i].data;
        }

        if (rp_http_add_referer(cf, rlcf->keys, &value[i], &uri) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_add_referer(rp_conf_t *cf, rp_hash_keys_arrays_t *keys,
    rp_str_t *value, rp_str_t *uri)
{
    rp_int_t   rc;
    rp_str_t  *u;

    if (uri == NULL || uri->len == 0) {
        u = RP_HTTP_REFERER_NO_URI_PART;

    } else {
        u = rp_palloc(cf->pool, sizeof(rp_str_t));
        if (u == NULL) {
            return RP_ERROR;
        }

        *u = *uri;
    }

    rc = rp_hash_add_key(keys, value, u, RP_HASH_WILDCARD_KEY);

    if (rc == RP_OK) {
        return RP_OK;
    }

    if (rc == RP_DECLINED) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid hostname or wildcard \"%V\"", value);
    }

    if (rc == RP_BUSY) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "conflicting parameter \"%V\"", value);
    }

    return RP_ERROR;
}


static rp_int_t
rp_http_add_regex_referer(rp_conf_t *cf, rp_http_referer_conf_t *rlcf,
    rp_str_t *name)
{
#if (RP_PCRE)
    rp_regex_elt_t      *re;
    rp_regex_compile_t   rc;
    u_char                errstr[RP_MAX_CONF_ERRSTR];

    if (name->len == 1) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0, "empty regex in \"%V\"", name);
        return RP_ERROR;
    }

    if (rlcf->regex == RP_CONF_UNSET_PTR) {
        rlcf->regex = rp_array_create(cf->pool, 2, sizeof(rp_regex_elt_t));
        if (rlcf->regex == NULL) {
            return RP_ERROR;
        }
    }

    re = rp_array_push(rlcf->regex);
    if (re == NULL) {
        return RP_ERROR;
    }

    name->len--;
    name->data++;

    rp_memzero(&rc, sizeof(rp_regex_compile_t));

    rc.pattern = *name;
    rc.pool = cf->pool;
    rc.options = RP_REGEX_CASELESS;
    rc.err.len = RP_MAX_CONF_ERRSTR;
    rc.err.data = errstr;

    if (rp_regex_compile(&rc) != RP_OK) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0, "%V", &rc.err);
        return RP_ERROR;
    }

    re->regex = rc.regex;
    re->name = name->data;

    return RP_OK;

#else

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "the using of the regex \"%V\" requires PCRE library",
                       name);

    return RP_ERROR;

#endif
}


#if (RP_PCRE)

static rp_int_t
rp_http_add_regex_server_name(rp_conf_t *cf, rp_http_referer_conf_t *rlcf,
    rp_http_regex_t *regex)
{
    rp_regex_elt_t  *re;

    if (rlcf->server_name_regex == RP_CONF_UNSET_PTR) {
        rlcf->server_name_regex = rp_array_create(cf->pool, 2,
                                                   sizeof(rp_regex_elt_t));
        if (rlcf->server_name_regex == NULL) {
            return RP_ERROR;
        }
    }

    re = rp_array_push(rlcf->server_name_regex);
    if (re == NULL) {
        return RP_ERROR;
    }

    re->regex = regex->regex;
    re->name = regex->name.data;

    return RP_OK;
}

#endif


static int rp_libc_cdecl
rp_http_cmp_referer_wildcards(const void *one, const void *two)
{
    rp_hash_key_t  *first, *second;

    first = (rp_hash_key_t *) one;
    second = (rp_hash_key_t *) two;

    return rp_dns_strcmp(first->key.data, second->key.data);
}
