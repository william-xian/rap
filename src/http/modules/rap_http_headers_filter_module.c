
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct rap_http_header_val_s  rap_http_header_val_t;

typedef rap_int_t (*rap_http_set_header_pt)(rap_http_request_t *r,
    rap_http_header_val_t *hv, rap_str_t *value);


typedef struct {
    rap_str_t                  name;
    rap_uint_t                 offset;
    rap_http_set_header_pt     handler;
} rap_http_set_header_t;


struct rap_http_header_val_s {
    rap_http_complex_value_t   value;
    rap_str_t                  key;
    rap_http_set_header_pt     handler;
    rap_uint_t                 offset;
    rap_uint_t                 always;  /* unsigned  always:1 */
};


typedef enum {
    RAP_HTTP_EXPIRES_OFF,
    RAP_HTTP_EXPIRES_EPOCH,
    RAP_HTTP_EXPIRES_MAX,
    RAP_HTTP_EXPIRES_ACCESS,
    RAP_HTTP_EXPIRES_MODIFIED,
    RAP_HTTP_EXPIRES_DAILY,
    RAP_HTTP_EXPIRES_UNSET
} rap_http_expires_t;


typedef struct {
    rap_http_expires_t         expires;
    time_t                     expires_time;
    rap_http_complex_value_t  *expires_value;
    rap_array_t               *headers;
    rap_array_t               *trailers;
} rap_http_headers_conf_t;


static rap_int_t rap_http_set_expires(rap_http_request_t *r,
    rap_http_headers_conf_t *conf);
static rap_int_t rap_http_parse_expires(rap_str_t *value,
    rap_http_expires_t *expires, time_t *expires_time, char **err);
static rap_int_t rap_http_add_multi_header_lines(rap_http_request_t *r,
    rap_http_header_val_t *hv, rap_str_t *value);
static rap_int_t rap_http_add_header(rap_http_request_t *r,
    rap_http_header_val_t *hv, rap_str_t *value);
static rap_int_t rap_http_set_last_modified(rap_http_request_t *r,
    rap_http_header_val_t *hv, rap_str_t *value);
static rap_int_t rap_http_set_response_header(rap_http_request_t *r,
    rap_http_header_val_t *hv, rap_str_t *value);

static void *rap_http_headers_create_conf(rap_conf_t *cf);
static char *rap_http_headers_merge_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_headers_filter_init(rap_conf_t *cf);
static char *rap_http_headers_expires(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_headers_add(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_http_set_header_t  rap_http_set_headers[] = {

    { rap_string("Cache-Control"),
                 offsetof(rap_http_headers_out_t, cache_control),
                 rap_http_add_multi_header_lines },

    { rap_string("Link"),
                 offsetof(rap_http_headers_out_t, link),
                 rap_http_add_multi_header_lines },

    { rap_string("Last-Modified"),
                 offsetof(rap_http_headers_out_t, last_modified),
                 rap_http_set_last_modified },

    { rap_string("ETag"),
                 offsetof(rap_http_headers_out_t, etag),
                 rap_http_set_response_header },

    { rap_null_string, 0, NULL }
};


static rap_command_t  rap_http_headers_filter_commands[] = {

    { rap_string("expires"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_TAKE12,
      rap_http_headers_expires,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("add_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_TAKE23,
      rap_http_headers_add,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_headers_conf_t, headers),
      NULL },

    { rap_string("add_trailer"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF
                        |RAP_CONF_TAKE23,
      rap_http_headers_add,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_headers_conf_t, trailers),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_headers_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_headers_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_headers_create_conf,          /* create location configuration */
    rap_http_headers_merge_conf            /* merge location configuration */
};


rap_module_t  rap_http_headers_filter_module = {
    RAP_MODULE_V1,
    &rap_http_headers_filter_module_ctx,   /* module context */
    rap_http_headers_filter_commands,      /* module directives */
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


static rap_http_output_header_filter_pt  rap_http_next_header_filter;
static rap_http_output_body_filter_pt    rap_http_next_body_filter;


static rap_int_t
rap_http_headers_filter(rap_http_request_t *r)
{
    rap_str_t                 value;
    rap_uint_t                i, safe_status;
    rap_http_header_val_t    *h;
    rap_http_headers_conf_t  *conf;

    if (r != r->main) {
        return rap_http_next_header_filter(r);
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_headers_filter_module);

    if (conf->expires == RAP_HTTP_EXPIRES_OFF
        && conf->headers == NULL
        && conf->trailers == NULL)
    {
        return rap_http_next_header_filter(r);
    }

    switch (r->headers_out.status) {

    case RAP_HTTP_OK:
    case RAP_HTTP_CREATED:
    case RAP_HTTP_NO_CONTENT:
    case RAP_HTTP_PARTIAL_CONTENT:
    case RAP_HTTP_MOVED_PERMANENTLY:
    case RAP_HTTP_MOVED_TEMPORARILY:
    case RAP_HTTP_SEE_OTHER:
    case RAP_HTTP_NOT_MODIFIED:
    case RAP_HTTP_TEMPORARY_REDIRECT:
    case RAP_HTTP_PERMANENT_REDIRECT:
        safe_status = 1;
        break;

    default:
        safe_status = 0;
        break;
    }

    if (conf->expires != RAP_HTTP_EXPIRES_OFF && safe_status) {
        if (rap_http_set_expires(r, conf) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    if (conf->headers) {
        h = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {

            if (!safe_status && !h[i].always) {
                continue;
            }

            if (rap_http_complex_value(r, &h[i].value, &value) != RAP_OK) {
                return RAP_ERROR;
            }

            if (h[i].handler(r, &h[i], &value) != RAP_OK) {
                return RAP_ERROR;
            }
        }
    }

    if (conf->trailers) {
        h = conf->trailers->elts;
        for (i = 0; i < conf->trailers->nelts; i++) {

            if (!safe_status && !h[i].always) {
                continue;
            }

            r->expect_trailers = 1;
            break;
        }
    }

    return rap_http_next_header_filter(r);
}


static rap_int_t
rap_http_trailers_filter(rap_http_request_t *r, rap_chain_t *in)
{
    rap_str_t                 value;
    rap_uint_t                i, safe_status;
    rap_chain_t              *cl;
    rap_table_elt_t          *t;
    rap_http_header_val_t    *h;
    rap_http_headers_conf_t  *conf;

    conf = rap_http_get_module_loc_conf(r, rap_http_headers_filter_module);

    if (in == NULL
        || conf->trailers == NULL
        || !r->expect_trailers
        || r->header_only)
    {
        return rap_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            break;
        }
    }

    if (cl == NULL) {
        return rap_http_next_body_filter(r, in);
    }

    switch (r->headers_out.status) {

    case RAP_HTTP_OK:
    case RAP_HTTP_CREATED:
    case RAP_HTTP_NO_CONTENT:
    case RAP_HTTP_PARTIAL_CONTENT:
    case RAP_HTTP_MOVED_PERMANENTLY:
    case RAP_HTTP_MOVED_TEMPORARILY:
    case RAP_HTTP_SEE_OTHER:
    case RAP_HTTP_NOT_MODIFIED:
    case RAP_HTTP_TEMPORARY_REDIRECT:
    case RAP_HTTP_PERMANENT_REDIRECT:
        safe_status = 1;
        break;

    default:
        safe_status = 0;
        break;
    }

    h = conf->trailers->elts;
    for (i = 0; i < conf->trailers->nelts; i++) {

        if (!safe_status && !h[i].always) {
            continue;
        }

        if (rap_http_complex_value(r, &h[i].value, &value) != RAP_OK) {
            return RAP_ERROR;
        }

        if (value.len) {
            t = rap_list_push(&r->headers_out.trailers);
            if (t == NULL) {
                return RAP_ERROR;
            }

            t->key = h[i].key;
            t->value = value;
            t->hash = 1;
        }
    }

    return rap_http_next_body_filter(r, in);
}


static rap_int_t
rap_http_set_expires(rap_http_request_t *r, rap_http_headers_conf_t *conf)
{
    char                *err;
    size_t               len;
    time_t               now, expires_time, max_age;
    rap_str_t            value;
    rap_int_t            rc;
    rap_uint_t           i;
    rap_table_elt_t     *e, *cc, **ccp;
    rap_http_expires_t   expires;

    expires = conf->expires;
    expires_time = conf->expires_time;

    if (conf->expires_value != NULL) {

        if (rap_http_complex_value(r, conf->expires_value, &value) != RAP_OK) {
            return RAP_ERROR;
        }

        rc = rap_http_parse_expires(&value, &expires, &expires_time, &err);

        if (rc != RAP_OK) {
            return RAP_OK;
        }

        if (expires == RAP_HTTP_EXPIRES_OFF) {
            return RAP_OK;
        }
    }

    e = r->headers_out.expires;

    if (e == NULL) {

        e = rap_list_push(&r->headers_out.headers);
        if (e == NULL) {
            return RAP_ERROR;
        }

        r->headers_out.expires = e;

        e->hash = 1;
        rap_str_set(&e->key, "Expires");
    }

    len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
    e->value.len = len - 1;

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (rap_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(rap_table_elt_t *))
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        cc = rap_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return RAP_ERROR;
        }

        cc->hash = 1;
        rap_str_set(&cc->key, "Cache-Control");

        ccp = rap_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return RAP_ERROR;
        }

        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }

    if (expires == RAP_HTTP_EXPIRES_EPOCH) {
        e->value.data = (u_char *) "Thu, 01 Jan 1970 00:00:01 GMT";
        rap_str_set(&cc->value, "no-cache");
        return RAP_OK;
    }

    if (expires == RAP_HTTP_EXPIRES_MAX) {
        e->value.data = (u_char *) "Thu, 31 Dec 2037 23:55:55 GMT";
        /* 10 years */
        rap_str_set(&cc->value, "max-age=315360000");
        return RAP_OK;
    }

    e->value.data = rap_pnalloc(r->pool, len);
    if (e->value.data == NULL) {
        return RAP_ERROR;
    }

    if (expires_time == 0 && expires != RAP_HTTP_EXPIRES_DAILY) {
        rap_memcpy(e->value.data, rap_cached_http_time.data,
                   rap_cached_http_time.len + 1);
        rap_str_set(&cc->value, "max-age=0");
        return RAP_OK;
    }

    now = rap_time();

    if (expires == RAP_HTTP_EXPIRES_DAILY) {
        expires_time = rap_next_time(expires_time);
        max_age = expires_time - now;

    } else if (expires == RAP_HTTP_EXPIRES_ACCESS
               || r->headers_out.last_modified_time == -1)
    {
        max_age = expires_time;
        expires_time += now;

    } else {
        expires_time += r->headers_out.last_modified_time;
        max_age = expires_time - now;
    }

    rap_http_time(e->value.data, expires_time);

    if (conf->expires_time < 0 || max_age < 0) {
        rap_str_set(&cc->value, "no-cache");
        return RAP_OK;
    }

    cc->value.data = rap_pnalloc(r->pool,
                                 sizeof("max-age=") + RAP_TIME_T_LEN + 1);
    if (cc->value.data == NULL) {
        return RAP_ERROR;
    }

    cc->value.len = rap_sprintf(cc->value.data, "max-age=%T", max_age)
                    - cc->value.data;

    return RAP_OK;
}


static rap_int_t
rap_http_parse_expires(rap_str_t *value, rap_http_expires_t *expires,
    time_t *expires_time, char **err)
{
    rap_uint_t  minus;

    if (*expires != RAP_HTTP_EXPIRES_MODIFIED) {

        if (value->len == 5 && rap_strncmp(value->data, "epoch", 5) == 0) {
            *expires = RAP_HTTP_EXPIRES_EPOCH;
            return RAP_OK;
        }

        if (value->len == 3 && rap_strncmp(value->data, "max", 3) == 0) {
            *expires = RAP_HTTP_EXPIRES_MAX;
            return RAP_OK;
        }

        if (value->len == 3 && rap_strncmp(value->data, "off", 3) == 0) {
            *expires = RAP_HTTP_EXPIRES_OFF;
            return RAP_OK;
        }
    }

    if (value->len && value->data[0] == '@') {
        value->data++;
        value->len--;
        minus = 0;

        if (*expires == RAP_HTTP_EXPIRES_MODIFIED) {
            *err = "daily time cannot be used with \"modified\" parameter";
            return RAP_ERROR;
        }

        *expires = RAP_HTTP_EXPIRES_DAILY;

    } else if (value->len && value->data[0] == '+') {
        value->data++;
        value->len--;
        minus = 0;

    } else if (value->len && value->data[0] == '-') {
        value->data++;
        value->len--;
        minus = 1;

    } else {
        minus = 0;
    }

    *expires_time = rap_parse_time(value, 1);

    if (*expires_time == (time_t) RAP_ERROR) {
        *err = "invalid value";
        return RAP_ERROR;
    }

    if (*expires == RAP_HTTP_EXPIRES_DAILY
        && *expires_time > 24 * 60 * 60)
    {
        *err = "daily time value must be less than 24 hours";
        return RAP_ERROR;
    }

    if (minus) {
        *expires_time = - *expires_time;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_add_header(rap_http_request_t *r, rap_http_header_val_t *hv,
    rap_str_t *value)
{
    rap_table_elt_t  *h;

    if (value->len) {
        h = rap_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return RAP_ERROR;
        }

        h->hash = 1;
        h->key = hv->key;
        h->value = *value;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_add_multi_header_lines(rap_http_request_t *r,
    rap_http_header_val_t *hv, rap_str_t *value)
{
    rap_array_t      *pa;
    rap_table_elt_t  *h, **ph;

    if (value->len == 0) {
        return RAP_OK;
    }

    pa = (rap_array_t *) ((char *) &r->headers_out + hv->offset);

    if (pa->elts == NULL) {
        if (rap_array_init(pa, r->pool, 1, sizeof(rap_table_elt_t *)) != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

    h = rap_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    h->hash = 1;
    h->key = hv->key;
    h->value = *value;

    ph = rap_array_push(pa);
    if (ph == NULL) {
        return RAP_ERROR;
    }

    *ph = h;

    return RAP_OK;
}


static rap_int_t
rap_http_set_last_modified(rap_http_request_t *r, rap_http_header_val_t *hv,
    rap_str_t *value)
{
    if (rap_http_set_response_header(r, hv, value) != RAP_OK) {
        return RAP_ERROR;
    }

    r->headers_out.last_modified_time =
        (value->len) ? rap_parse_http_time(value->data, value->len) : -1;

    return RAP_OK;
}


static rap_int_t
rap_http_set_response_header(rap_http_request_t *r, rap_http_header_val_t *hv,
    rap_str_t *value)
{
    rap_table_elt_t  *h, **old;

    old = (rap_table_elt_t **) ((char *) &r->headers_out + hv->offset);

    if (value->len == 0) {
        if (*old) {
            (*old)->hash = 0;
            *old = NULL;
        }

        return RAP_OK;
    }

    if (*old) {
        h = *old;

    } else {
        h = rap_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return RAP_ERROR;
        }

        *old = h;
    }

    h->hash = 1;
    h->key = hv->key;
    h->value = *value;

    return RAP_OK;
}


static void *
rap_http_headers_create_conf(rap_conf_t *cf)
{
    rap_http_headers_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_headers_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->headers = NULL;
     *     conf->trailers = NULL;
     *     conf->expires_time = 0;
     *     conf->expires_value = NULL;
     */

    conf->expires = RAP_HTTP_EXPIRES_UNSET;

    return conf;
}


static char *
rap_http_headers_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_headers_conf_t *prev = parent;
    rap_http_headers_conf_t *conf = child;

    if (conf->expires == RAP_HTTP_EXPIRES_UNSET) {
        conf->expires = prev->expires;
        conf->expires_time = prev->expires_time;
        conf->expires_value = prev->expires_value;

        if (conf->expires == RAP_HTTP_EXPIRES_UNSET) {
            conf->expires = RAP_HTTP_EXPIRES_OFF;
        }
    }

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
    }

    if (conf->trailers == NULL) {
        conf->trailers = prev->trailers;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_headers_filter_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_headers_filter;

    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_trailers_filter;

    return RAP_OK;
}


static char *
rap_http_headers_expires(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_headers_conf_t *hcf = conf;

    char                              *err;
    rap_str_t                         *value;
    rap_int_t                          rc;
    rap_uint_t                         n;
    rap_http_complex_value_t           cv;
    rap_http_compile_complex_value_t   ccv;

    if (hcf->expires != RAP_HTTP_EXPIRES_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        hcf->expires = RAP_HTTP_EXPIRES_ACCESS;

        n = 1;

    } else { /* cf->args->nelts == 3 */

        if (rap_strcmp(value[1].data, "modified") != 0) {
            return "invalid value";
        }

        hcf->expires = RAP_HTTP_EXPIRES_MODIFIED;

        n = 2;
    }

    rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[n];
    ccv.complex_value = &cv;

    if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
        return RAP_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        hcf->expires_value = rap_palloc(cf->pool,
                                        sizeof(rap_http_complex_value_t));
        if (hcf->expires_value == NULL) {
            return RAP_CONF_ERROR;
        }

        *hcf->expires_value = cv;

        return RAP_CONF_OK;
    }

    rc = rap_http_parse_expires(&value[n], &hcf->expires, &hcf->expires_time,
                                &err);
    if (rc != RAP_OK) {
        return err;
    }

    return RAP_CONF_OK;
}


static char *
rap_http_headers_add(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_headers_conf_t *hcf = conf;

    rap_str_t                          *value;
    rap_uint_t                          i;
    rap_array_t                       **headers;
    rap_http_header_val_t              *hv;
    rap_http_set_header_t              *set;
    rap_http_compile_complex_value_t    ccv;

    value = cf->args->elts;

    headers = (rap_array_t **) ((char *) hcf + cmd->offset);

    if (*headers == NULL) {
        *headers = rap_array_create(cf->pool, 1,
                                    sizeof(rap_http_header_val_t));
        if (*headers == NULL) {
            return RAP_CONF_ERROR;
        }
    }

    hv = rap_array_push(*headers);
    if (hv == NULL) {
        return RAP_CONF_ERROR;
    }

    hv->key = value[1];
    hv->handler = NULL;
    hv->offset = 0;
    hv->always = 0;

    if (headers == &hcf->headers) {
        hv->handler = rap_http_add_header;

        set = rap_http_set_headers;
        for (i = 0; set[i].name.len; i++) {
            if (rap_strcasecmp(value[1].data, set[i].name.data) != 0) {
                continue;
            }

            hv->offset = set[i].offset;
            hv->handler = set[i].handler;

            break;
        }
    }

    if (value[2].len == 0) {
        rap_memzero(&hv->value, sizeof(rap_http_complex_value_t));

    } else {
        rap_memzero(&ccv, sizeof(rap_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[2];
        ccv.complex_value = &hv->value;

        if (rap_http_compile_complex_value(&ccv) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    if (cf->args->nelts == 3) {
        return RAP_CONF_OK;
    }

    if (rap_strcmp(value[3].data, "always") != 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[3]);
        return RAP_CONF_ERROR;
    }

    hv->always = 1;

    return RAP_CONF_OK;
}
