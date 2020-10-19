
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap_md5.h>


typedef struct {
    rap_http_complex_value_t  *variable;
    rap_http_complex_value_t  *md5;
    rap_str_t                  secret;
} rap_http_secure_link_conf_t;


typedef struct {
    rap_str_t                  expires;
} rap_http_secure_link_ctx_t;


static rap_int_t rap_http_secure_link_old_variable(rap_http_request_t *r,
    rap_http_secure_link_conf_t *conf, rap_http_variable_value_t *v,
    uintptr_t data);
static rap_int_t rap_http_secure_link_expires_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static void *rap_http_secure_link_create_conf(rap_conf_t *cf);
static char *rap_http_secure_link_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static rap_int_t rap_http_secure_link_add_variables(rap_conf_t *cf);


static rap_command_t  rap_http_secure_link_commands[] = {

    { rap_string("secure_link"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_set_complex_value_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_secure_link_conf_t, variable),
      NULL },

    { rap_string("secure_link_md5"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_set_complex_value_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_secure_link_conf_t, md5),
      NULL },

    { rap_string("secure_link_secret"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_secure_link_conf_t, secret),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_secure_link_module_ctx = {
    rap_http_secure_link_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_secure_link_create_conf,      /* create location configuration */
    rap_http_secure_link_merge_conf        /* merge location configuration */
};


rap_module_t  rap_http_secure_link_module = {
    RAP_MODULE_V1,
    &rap_http_secure_link_module_ctx,      /* module context */
    rap_http_secure_link_commands,         /* module directives */
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


static rap_str_t  rap_http_secure_link_name = rap_string("secure_link");
static rap_str_t  rap_http_secure_link_expires_name =
    rap_string("secure_link_expires");


static rap_int_t
rap_http_secure_link_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char                       *p, *last;
    rap_str_t                     val, hash;
    time_t                        expires;
    rap_md5_t                     md5;
    rap_http_secure_link_ctx_t   *ctx;
    rap_http_secure_link_conf_t  *conf;
    u_char                        hash_buf[18], md5_buf[16];

    conf = rap_http_get_module_loc_conf(r, rap_http_secure_link_module);

    if (conf->secret.data) {
        return rap_http_secure_link_old_variable(r, conf, v, data);
    }

    if (conf->variable == NULL || conf->md5 == NULL) {
        goto not_found;
    }

    if (rap_http_complex_value(r, conf->variable, &val) != RAP_OK) {
        return RAP_ERROR;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link: \"%V\"", &val);

    last = val.data + val.len;

    p = rap_strlchr(val.data, last, ',');
    expires = 0;

    if (p) {
        val.len = p++ - val.data;

        expires = rap_atotm(p, last - p);
        if (expires <= 0) {
            goto not_found;
        }

        ctx = rap_pcalloc(r->pool, sizeof(rap_http_secure_link_ctx_t));
        if (ctx == NULL) {
            return RAP_ERROR;
        }

        rap_http_set_ctx(r, ctx, rap_http_secure_link_module);

        ctx->expires.len = last - p;
        ctx->expires.data = p;
    }

    if (val.len > 24) {
        goto not_found;
    }

    hash.data = hash_buf;

    if (rap_decode_base64url(&hash, &val) != RAP_OK) {
        goto not_found;
    }

    if (hash.len != 16) {
        goto not_found;
    }

    if (rap_http_complex_value(r, conf->md5, &val) != RAP_OK) {
        return RAP_ERROR;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link md5: \"%V\"", &val);

    rap_md5_init(&md5);
    rap_md5_update(&md5, val.data, val.len);
    rap_md5_final(md5_buf, &md5);

    if (rap_memcmp(hash_buf, md5_buf, 16) != 0) {
        goto not_found;
    }

    v->data = (u_char *) ((expires && expires < rap_time()) ? "0" : "1");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;

not_found:

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_secure_link_old_variable(rap_http_request_t *r,
    rap_http_secure_link_conf_t *conf, rap_http_variable_value_t *v,
    uintptr_t data)
{
    u_char      *p, *start, *end, *last;
    size_t       len;
    rap_int_t    n;
    rap_uint_t   i;
    rap_md5_t    md5;
    u_char       hash[16];

    p = &r->unparsed_uri.data[1];
    last = r->unparsed_uri.data + r->unparsed_uri.len;

    while (p < last) {
        if (*p++ == '/') {
            start = p;
            goto md5_start;
        }
    }

    goto not_found;

md5_start:

    while (p < last) {
        if (*p++ == '/') {
            end = p - 1;
            goto url_start;
        }
    }

    goto not_found;

url_start:

    len = last - p;

    if (end - start != 32 || len == 0) {
        goto not_found;
    }

    rap_md5_init(&md5);
    rap_md5_update(&md5, p, len);
    rap_md5_update(&md5, conf->secret.data, conf->secret.len);
    rap_md5_final(hash, &md5);

    for (i = 0; i < 16; i++) {
        n = rap_hextoi(&start[2 * i], 2);
        if (n == RAP_ERROR || n != hash[i]) {
            goto not_found;
        }
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;

not_found:

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_secure_link_expires_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_secure_link_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_secure_link_module);

    if (ctx) {
        v->len = ctx->expires.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ctx->expires.data;

    } else {
        v->not_found = 1;
    }

    return RAP_OK;
}


static void *
rap_http_secure_link_create_conf(rap_conf_t *cf)
{
    rap_http_secure_link_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_secure_link_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->variable = NULL;
     *     conf->md5 = NULL;
     *     conf->secret = { 0, NULL };
     */

    return conf;
}


static char *
rap_http_secure_link_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_secure_link_conf_t *prev = parent;
    rap_http_secure_link_conf_t *conf = child;

    if (conf->secret.data) {
        if (conf->variable || conf->md5) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "\"secure_link_secret\" cannot be mixed with "
                               "\"secure_link\" and \"secure_link_md5\"");
            return RAP_CONF_ERROR;
        }

        return RAP_CONF_OK;
    }

    if (conf->variable == NULL) {
        conf->variable = prev->variable;
    }

    if (conf->md5 == NULL) {
        conf->md5 = prev->md5;
    }

    if (conf->variable == NULL && conf->md5 == NULL) {
        conf->secret = prev->secret;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_secure_link_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var;

    var = rap_http_add_variable(cf, &rap_http_secure_link_name, 0);
    if (var == NULL) {
        return RAP_ERROR;
    }

    var->get_handler = rap_http_secure_link_variable;

    var = rap_http_add_variable(cf, &rap_http_secure_link_expires_name, 0);
    if (var == NULL) {
        return RAP_ERROR;
    }

    var->get_handler = rap_http_secure_link_expires_variable;

    return RAP_OK;
}
