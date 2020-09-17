
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rp_md5.h>


typedef struct {
    rp_http_complex_value_t  *variable;
    rp_http_complex_value_t  *md5;
    rp_str_t                  secret;
} rp_http_secure_link_conf_t;


typedef struct {
    rp_str_t                  expires;
} rp_http_secure_link_ctx_t;


static rp_int_t rp_http_secure_link_old_variable(rp_http_request_t *r,
    rp_http_secure_link_conf_t *conf, rp_http_variable_value_t *v,
    uintptr_t data);
static rp_int_t rp_http_secure_link_expires_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static void *rp_http_secure_link_create_conf(rp_conf_t *cf);
static char *rp_http_secure_link_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static rp_int_t rp_http_secure_link_add_variables(rp_conf_t *cf);


static rp_command_t  rp_http_secure_link_commands[] = {

    { rp_string("secure_link"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_set_complex_value_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_secure_link_conf_t, variable),
      NULL },

    { rp_string("secure_link_md5"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_set_complex_value_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_secure_link_conf_t, md5),
      NULL },

    { rp_string("secure_link_secret"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_secure_link_conf_t, secret),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_secure_link_module_ctx = {
    rp_http_secure_link_add_variables,    /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_secure_link_create_conf,      /* create location configuration */
    rp_http_secure_link_merge_conf        /* merge location configuration */
};


rp_module_t  rp_http_secure_link_module = {
    RP_MODULE_V1,
    &rp_http_secure_link_module_ctx,      /* module context */
    rp_http_secure_link_commands,         /* module directives */
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


static rp_str_t  rp_http_secure_link_name = rp_string("secure_link");
static rp_str_t  rp_http_secure_link_expires_name =
    rp_string("secure_link_expires");


static rp_int_t
rp_http_secure_link_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char                       *p, *last;
    rp_str_t                     val, hash;
    time_t                        expires;
    rp_md5_t                     md5;
    rp_http_secure_link_ctx_t   *ctx;
    rp_http_secure_link_conf_t  *conf;
    u_char                        hash_buf[18], md5_buf[16];

    conf = rp_http_get_module_loc_conf(r, rp_http_secure_link_module);

    if (conf->secret.data) {
        return rp_http_secure_link_old_variable(r, conf, v, data);
    }

    if (conf->variable == NULL || conf->md5 == NULL) {
        goto not_found;
    }

    if (rp_http_complex_value(r, conf->variable, &val) != RP_OK) {
        return RP_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link: \"%V\"", &val);

    last = val.data + val.len;

    p = rp_strlchr(val.data, last, ',');
    expires = 0;

    if (p) {
        val.len = p++ - val.data;

        expires = rp_atotm(p, last - p);
        if (expires <= 0) {
            goto not_found;
        }

        ctx = rp_pcalloc(r->pool, sizeof(rp_http_secure_link_ctx_t));
        if (ctx == NULL) {
            return RP_ERROR;
        }

        rp_http_set_ctx(r, ctx, rp_http_secure_link_module);

        ctx->expires.len = last - p;
        ctx->expires.data = p;
    }

    if (val.len > 24) {
        goto not_found;
    }

    hash.data = hash_buf;

    if (rp_decode_base64url(&hash, &val) != RP_OK) {
        goto not_found;
    }

    if (hash.len != 16) {
        goto not_found;
    }

    if (rp_http_complex_value(r, conf->md5, &val) != RP_OK) {
        return RP_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "secure link md5: \"%V\"", &val);

    rp_md5_init(&md5);
    rp_md5_update(&md5, val.data, val.len);
    rp_md5_final(md5_buf, &md5);

    if (rp_memcmp(hash_buf, md5_buf, 16) != 0) {
        goto not_found;
    }

    v->data = (u_char *) ((expires && expires < rp_time()) ? "0" : "1");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RP_OK;

not_found:

    v->not_found = 1;

    return RP_OK;
}


static rp_int_t
rp_http_secure_link_old_variable(rp_http_request_t *r,
    rp_http_secure_link_conf_t *conf, rp_http_variable_value_t *v,
    uintptr_t data)
{
    u_char      *p, *start, *end, *last;
    size_t       len;
    rp_int_t    n;
    rp_uint_t   i;
    rp_md5_t    md5;
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

    rp_md5_init(&md5);
    rp_md5_update(&md5, p, len);
    rp_md5_update(&md5, conf->secret.data, conf->secret.len);
    rp_md5_final(hash, &md5);

    for (i = 0; i < 16; i++) {
        n = rp_hextoi(&start[2 * i], 2);
        if (n == RP_ERROR || n != hash[i]) {
            goto not_found;
        }
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;

not_found:

    v->not_found = 1;

    return RP_OK;
}


static rp_int_t
rp_http_secure_link_expires_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_http_secure_link_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_secure_link_module);

    if (ctx) {
        v->len = ctx->expires.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = ctx->expires.data;

    } else {
        v->not_found = 1;
    }

    return RP_OK;
}


static void *
rp_http_secure_link_create_conf(rp_conf_t *cf)
{
    rp_http_secure_link_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_secure_link_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->variable = NULL;
     *     conf->md5 = NULL;
     *     conf->secret = { 0, NULL };
     */

    return conf;
}


static char *
rp_http_secure_link_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_secure_link_conf_t *prev = parent;
    rp_http_secure_link_conf_t *conf = child;

    if (conf->secret.data) {
        if (conf->variable || conf->md5) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "\"secure_link_secret\" cannot be mixed with "
                               "\"secure_link\" and \"secure_link_md5\"");
            return RP_CONF_ERROR;
        }

        return RP_CONF_OK;
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

    return RP_CONF_OK;
}


static rp_int_t
rp_http_secure_link_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var;

    var = rp_http_add_variable(cf, &rp_http_secure_link_name, 0);
    if (var == NULL) {
        return RP_ERROR;
    }

    var->get_handler = rp_http_secure_link_variable;

    var = rp_http_add_variable(cf, &rp_http_secure_link_expires_name, 0);
    if (var == NULL) {
        return RP_ERROR;
    }

    var->get_handler = rp_http_secure_link_expires_variable;

    return RP_OK;
}
