
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct rp_http_header_val_s  rp_http_header_val_t;

typedef rp_int_t (*rp_http_set_header_pt)(rp_http_request_t *r,
    rp_http_header_val_t *hv, rp_str_t *value);


typedef struct {
    rp_str_t                  name;
    rp_uint_t                 offset;
    rp_http_set_header_pt     handler;
} rp_http_set_header_t;


struct rp_http_header_val_s {
    rp_http_complex_value_t   value;
    rp_str_t                  key;
    rp_http_set_header_pt     handler;
    rp_uint_t                 offset;
    rp_uint_t                 always;  /* unsigned  always:1 */
};


typedef enum {
    RP_HTTP_EXPIRES_OFF,
    RP_HTTP_EXPIRES_EPOCH,
    RP_HTTP_EXPIRES_MAX,
    RP_HTTP_EXPIRES_ACCESS,
    RP_HTTP_EXPIRES_MODIFIED,
    RP_HTTP_EXPIRES_DAILY,
    RP_HTTP_EXPIRES_UNSET
} rp_http_expires_t;


typedef struct {
    rp_http_expires_t         expires;
    time_t                     expires_time;
    rp_http_complex_value_t  *expires_value;
    rp_array_t               *headers;
    rp_array_t               *trailers;
} rp_http_headers_conf_t;


static rp_int_t rp_http_set_expires(rp_http_request_t *r,
    rp_http_headers_conf_t *conf);
static rp_int_t rp_http_parse_expires(rp_str_t *value,
    rp_http_expires_t *expires, time_t *expires_time, char **err);
static rp_int_t rp_http_add_multi_header_lines(rp_http_request_t *r,
    rp_http_header_val_t *hv, rp_str_t *value);
static rp_int_t rp_http_add_header(rp_http_request_t *r,
    rp_http_header_val_t *hv, rp_str_t *value);
static rp_int_t rp_http_set_last_modified(rp_http_request_t *r,
    rp_http_header_val_t *hv, rp_str_t *value);
static rp_int_t rp_http_set_response_header(rp_http_request_t *r,
    rp_http_header_val_t *hv, rp_str_t *value);

static void *rp_http_headers_create_conf(rp_conf_t *cf);
static char *rp_http_headers_merge_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_headers_filter_init(rp_conf_t *cf);
static char *rp_http_headers_expires(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_headers_add(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_http_set_header_t  rp_http_set_headers[] = {

    { rp_string("Cache-Control"),
                 offsetof(rp_http_headers_out_t, cache_control),
                 rp_http_add_multi_header_lines },

    { rp_string("Link"),
                 offsetof(rp_http_headers_out_t, link),
                 rp_http_add_multi_header_lines },

    { rp_string("Last-Modified"),
                 offsetof(rp_http_headers_out_t, last_modified),
                 rp_http_set_last_modified },

    { rp_string("ETag"),
                 offsetof(rp_http_headers_out_t, etag),
                 rp_http_set_response_header },

    { rp_null_string, 0, NULL }
};


static rp_command_t  rp_http_headers_filter_commands[] = {

    { rp_string("expires"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_TAKE12,
      rp_http_headers_expires,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("add_header"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_TAKE23,
      rp_http_headers_add,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_headers_conf_t, headers),
      NULL },

    { rp_string("add_trailer"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF
                        |RP_CONF_TAKE23,
      rp_http_headers_add,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_headers_conf_t, trailers),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_headers_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_headers_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_headers_create_conf,          /* create location configuration */
    rp_http_headers_merge_conf            /* merge location configuration */
};


rp_module_t  rp_http_headers_filter_module = {
    RP_MODULE_V1,
    &rp_http_headers_filter_module_ctx,   /* module context */
    rp_http_headers_filter_commands,      /* module directives */
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


static rp_http_output_header_filter_pt  rp_http_next_header_filter;
static rp_http_output_body_filter_pt    rp_http_next_body_filter;


static rp_int_t
rp_http_headers_filter(rp_http_request_t *r)
{
    rp_str_t                 value;
    rp_uint_t                i, safe_status;
    rp_http_header_val_t    *h;
    rp_http_headers_conf_t  *conf;

    if (r != r->main) {
        return rp_http_next_header_filter(r);
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_headers_filter_module);

    if (conf->expires == RP_HTTP_EXPIRES_OFF
        && conf->headers == NULL
        && conf->trailers == NULL)
    {
        return rp_http_next_header_filter(r);
    }

    switch (r->headers_out.status) {

    case RP_HTTP_OK:
    case RP_HTTP_CREATED:
    case RP_HTTP_NO_CONTENT:
    case RP_HTTP_PARTIAL_CONTENT:
    case RP_HTTP_MOVED_PERMANENTLY:
    case RP_HTTP_MOVED_TEMPORARILY:
    case RP_HTTP_SEE_OTHER:
    case RP_HTTP_NOT_MODIFIED:
    case RP_HTTP_TEMPORARY_REDIRECT:
    case RP_HTTP_PERMANENT_REDIRECT:
        safe_status = 1;
        break;

    default:
        safe_status = 0;
        break;
    }

    if (conf->expires != RP_HTTP_EXPIRES_OFF && safe_status) {
        if (rp_http_set_expires(r, conf) != RP_OK) {
            return RP_ERROR;
        }
    }

    if (conf->headers) {
        h = conf->headers->elts;
        for (i = 0; i < conf->headers->nelts; i++) {

            if (!safe_status && !h[i].always) {
                continue;
            }

            if (rp_http_complex_value(r, &h[i].value, &value) != RP_OK) {
                return RP_ERROR;
            }

            if (h[i].handler(r, &h[i], &value) != RP_OK) {
                return RP_ERROR;
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

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_trailers_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_str_t                 value;
    rp_uint_t                i, safe_status;
    rp_chain_t              *cl;
    rp_table_elt_t          *t;
    rp_http_header_val_t    *h;
    rp_http_headers_conf_t  *conf;

    conf = rp_http_get_module_loc_conf(r, rp_http_headers_filter_module);

    if (in == NULL
        || conf->trailers == NULL
        || !r->expect_trailers
        || r->header_only)
    {
        return rp_http_next_body_filter(r, in);
    }

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            break;
        }
    }

    if (cl == NULL) {
        return rp_http_next_body_filter(r, in);
    }

    switch (r->headers_out.status) {

    case RP_HTTP_OK:
    case RP_HTTP_CREATED:
    case RP_HTTP_NO_CONTENT:
    case RP_HTTP_PARTIAL_CONTENT:
    case RP_HTTP_MOVED_PERMANENTLY:
    case RP_HTTP_MOVED_TEMPORARILY:
    case RP_HTTP_SEE_OTHER:
    case RP_HTTP_NOT_MODIFIED:
    case RP_HTTP_TEMPORARY_REDIRECT:
    case RP_HTTP_PERMANENT_REDIRECT:
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

        if (rp_http_complex_value(r, &h[i].value, &value) != RP_OK) {
            return RP_ERROR;
        }

        if (value.len) {
            t = rp_list_push(&r->headers_out.trailers);
            if (t == NULL) {
                return RP_ERROR;
            }

            t->key = h[i].key;
            t->value = value;
            t->hash = 1;
        }
    }

    return rp_http_next_body_filter(r, in);
}


static rp_int_t
rp_http_set_expires(rp_http_request_t *r, rp_http_headers_conf_t *conf)
{
    char                *err;
    size_t               len;
    time_t               now, expires_time, max_age;
    rp_str_t            value;
    rp_int_t            rc;
    rp_uint_t           i;
    rp_table_elt_t     *e, *cc, **ccp;
    rp_http_expires_t   expires;

    expires = conf->expires;
    expires_time = conf->expires_time;

    if (conf->expires_value != NULL) {

        if (rp_http_complex_value(r, conf->expires_value, &value) != RP_OK) {
            return RP_ERROR;
        }

        rc = rp_http_parse_expires(&value, &expires, &expires_time, &err);

        if (rc != RP_OK) {
            return RP_OK;
        }

        if (expires == RP_HTTP_EXPIRES_OFF) {
            return RP_OK;
        }
    }

    e = r->headers_out.expires;

    if (e == NULL) {

        e = rp_list_push(&r->headers_out.headers);
        if (e == NULL) {
            return RP_ERROR;
        }

        r->headers_out.expires = e;

        e->hash = 1;
        rp_str_set(&e->key, "Expires");
    }

    len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT");
    e->value.len = len - 1;

    ccp = r->headers_out.cache_control.elts;

    if (ccp == NULL) {

        if (rp_array_init(&r->headers_out.cache_control, r->pool,
                           1, sizeof(rp_table_elt_t *))
            != RP_OK)
        {
            return RP_ERROR;
        }

        cc = rp_list_push(&r->headers_out.headers);
        if (cc == NULL) {
            return RP_ERROR;
        }

        cc->hash = 1;
        rp_str_set(&cc->key, "Cache-Control");

        ccp = rp_array_push(&r->headers_out.cache_control);
        if (ccp == NULL) {
            return RP_ERROR;
        }

        *ccp = cc;

    } else {
        for (i = 1; i < r->headers_out.cache_control.nelts; i++) {
            ccp[i]->hash = 0;
        }

        cc = ccp[0];
    }

    if (expires == RP_HTTP_EXPIRES_EPOCH) {
        e->value.data = (u_char *) "Thu, 01 Jan 1970 00:00:01 GMT";
        rp_str_set(&cc->value, "no-cache");
        return RP_OK;
    }

    if (expires == RP_HTTP_EXPIRES_MAX) {
        e->value.data = (u_char *) "Thu, 31 Dec 2037 23:55:55 GMT";
        /* 10 years */
        rp_str_set(&cc->value, "max-age=315360000");
        return RP_OK;
    }

    e->value.data = rp_pnalloc(r->pool, len);
    if (e->value.data == NULL) {
        return RP_ERROR;
    }

    if (expires_time == 0 && expires != RP_HTTP_EXPIRES_DAILY) {
        rp_memcpy(e->value.data, rp_cached_http_time.data,
                   rp_cached_http_time.len + 1);
        rp_str_set(&cc->value, "max-age=0");
        return RP_OK;
    }

    now = rp_time();

    if (expires == RP_HTTP_EXPIRES_DAILY) {
        expires_time = rp_next_time(expires_time);
        max_age = expires_time - now;

    } else if (expires == RP_HTTP_EXPIRES_ACCESS
               || r->headers_out.last_modified_time == -1)
    {
        max_age = expires_time;
        expires_time += now;

    } else {
        expires_time += r->headers_out.last_modified_time;
        max_age = expires_time - now;
    }

    rp_http_time(e->value.data, expires_time);

    if (conf->expires_time < 0 || max_age < 0) {
        rp_str_set(&cc->value, "no-cache");
        return RP_OK;
    }

    cc->value.data = rp_pnalloc(r->pool,
                                 sizeof("max-age=") + RP_TIME_T_LEN + 1);
    if (cc->value.data == NULL) {
        return RP_ERROR;
    }

    cc->value.len = rp_sprintf(cc->value.data, "max-age=%T", max_age)
                    - cc->value.data;

    return RP_OK;
}


static rp_int_t
rp_http_parse_expires(rp_str_t *value, rp_http_expires_t *expires,
    time_t *expires_time, char **err)
{
    rp_uint_t  minus;

    if (*expires != RP_HTTP_EXPIRES_MODIFIED) {

        if (value->len == 5 && rp_strncmp(value->data, "epoch", 5) == 0) {
            *expires = RP_HTTP_EXPIRES_EPOCH;
            return RP_OK;
        }

        if (value->len == 3 && rp_strncmp(value->data, "max", 3) == 0) {
            *expires = RP_HTTP_EXPIRES_MAX;
            return RP_OK;
        }

        if (value->len == 3 && rp_strncmp(value->data, "off", 3) == 0) {
            *expires = RP_HTTP_EXPIRES_OFF;
            return RP_OK;
        }
    }

    if (value->len && value->data[0] == '@') {
        value->data++;
        value->len--;
        minus = 0;

        if (*expires == RP_HTTP_EXPIRES_MODIFIED) {
            *err = "daily time cannot be used with \"modified\" parameter";
            return RP_ERROR;
        }

        *expires = RP_HTTP_EXPIRES_DAILY;

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

    *expires_time = rp_parse_time(value, 1);

    if (*expires_time == (time_t) RP_ERROR) {
        *err = "invalid value";
        return RP_ERROR;
    }

    if (*expires == RP_HTTP_EXPIRES_DAILY
        && *expires_time > 24 * 60 * 60)
    {
        *err = "daily time value must be less than 24 hours";
        return RP_ERROR;
    }

    if (minus) {
        *expires_time = - *expires_time;
    }

    return RP_OK;
}


static rp_int_t
rp_http_add_header(rp_http_request_t *r, rp_http_header_val_t *hv,
    rp_str_t *value)
{
    rp_table_elt_t  *h;

    if (value->len) {
        h = rp_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return RP_ERROR;
        }

        h->hash = 1;
        h->key = hv->key;
        h->value = *value;
    }

    return RP_OK;
}


static rp_int_t
rp_http_add_multi_header_lines(rp_http_request_t *r,
    rp_http_header_val_t *hv, rp_str_t *value)
{
    rp_array_t      *pa;
    rp_table_elt_t  *h, **ph;

    if (value->len == 0) {
        return RP_OK;
    }

    pa = (rp_array_t *) ((char *) &r->headers_out + hv->offset);

    if (pa->elts == NULL) {
        if (rp_array_init(pa, r->pool, 1, sizeof(rp_table_elt_t *)) != RP_OK)
        {
            return RP_ERROR;
        }
    }

    h = rp_list_push(&r->headers_out.headers);
    if (h == NULL) {
        return RP_ERROR;
    }

    h->hash = 1;
    h->key = hv->key;
    h->value = *value;

    ph = rp_array_push(pa);
    if (ph == NULL) {
        return RP_ERROR;
    }

    *ph = h;

    return RP_OK;
}


static rp_int_t
rp_http_set_last_modified(rp_http_request_t *r, rp_http_header_val_t *hv,
    rp_str_t *value)
{
    if (rp_http_set_response_header(r, hv, value) != RP_OK) {
        return RP_ERROR;
    }

    r->headers_out.last_modified_time =
        (value->len) ? rp_parse_http_time(value->data, value->len) : -1;

    return RP_OK;
}


static rp_int_t
rp_http_set_response_header(rp_http_request_t *r, rp_http_header_val_t *hv,
    rp_str_t *value)
{
    rp_table_elt_t  *h, **old;

    old = (rp_table_elt_t **) ((char *) &r->headers_out + hv->offset);

    if (value->len == 0) {
        if (*old) {
            (*old)->hash = 0;
            *old = NULL;
        }

        return RP_OK;
    }

    if (*old) {
        h = *old;

    } else {
        h = rp_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return RP_ERROR;
        }

        *old = h;
    }

    h->hash = 1;
    h->key = hv->key;
    h->value = *value;

    return RP_OK;
}


static void *
rp_http_headers_create_conf(rp_conf_t *cf)
{
    rp_http_headers_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_headers_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->headers = NULL;
     *     conf->trailers = NULL;
     *     conf->expires_time = 0;
     *     conf->expires_value = NULL;
     */

    conf->expires = RP_HTTP_EXPIRES_UNSET;

    return conf;
}


static char *
rp_http_headers_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_headers_conf_t *prev = parent;
    rp_http_headers_conf_t *conf = child;

    if (conf->expires == RP_HTTP_EXPIRES_UNSET) {
        conf->expires = prev->expires;
        conf->expires_time = prev->expires_time;
        conf->expires_value = prev->expires_value;

        if (conf->expires == RP_HTTP_EXPIRES_UNSET) {
            conf->expires = RP_HTTP_EXPIRES_OFF;
        }
    }

    if (conf->headers == NULL) {
        conf->headers = prev->headers;
    }

    if (conf->trailers == NULL) {
        conf->trailers = prev->trailers;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_headers_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_headers_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_trailers_filter;

    return RP_OK;
}


static char *
rp_http_headers_expires(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_headers_conf_t *hcf = conf;

    char                              *err;
    rp_str_t                         *value;
    rp_int_t                          rc;
    rp_uint_t                         n;
    rp_http_complex_value_t           cv;
    rp_http_compile_complex_value_t   ccv;

    if (hcf->expires != RP_HTTP_EXPIRES_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (cf->args->nelts == 2) {

        hcf->expires = RP_HTTP_EXPIRES_ACCESS;

        n = 1;

    } else { /* cf->args->nelts == 3 */

        if (rp_strcmp(value[1].data, "modified") != 0) {
            return "invalid value";
        }

        hcf->expires = RP_HTTP_EXPIRES_MODIFIED;

        n = 2;
    }

    rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[n];
    ccv.complex_value = &cv;

    if (rp_http_compile_complex_value(&ccv) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (cv.lengths != NULL) {

        hcf->expires_value = rp_palloc(cf->pool,
                                        sizeof(rp_http_complex_value_t));
        if (hcf->expires_value == NULL) {
            return RP_CONF_ERROR;
        }

        *hcf->expires_value = cv;

        return RP_CONF_OK;
    }

    rc = rp_http_parse_expires(&value[n], &hcf->expires, &hcf->expires_time,
                                &err);
    if (rc != RP_OK) {
        return err;
    }

    return RP_CONF_OK;
}


static char *
rp_http_headers_add(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_headers_conf_t *hcf = conf;

    rp_str_t                          *value;
    rp_uint_t                          i;
    rp_array_t                       **headers;
    rp_http_header_val_t              *hv;
    rp_http_set_header_t              *set;
    rp_http_compile_complex_value_t    ccv;

    value = cf->args->elts;

    headers = (rp_array_t **) ((char *) hcf + cmd->offset);

    if (*headers == NULL) {
        *headers = rp_array_create(cf->pool, 1,
                                    sizeof(rp_http_header_val_t));
        if (*headers == NULL) {
            return RP_CONF_ERROR;
        }
    }

    hv = rp_array_push(*headers);
    if (hv == NULL) {
        return RP_CONF_ERROR;
    }

    hv->key = value[1];
    hv->handler = NULL;
    hv->offset = 0;
    hv->always = 0;

    if (headers == &hcf->headers) {
        hv->handler = rp_http_add_header;

        set = rp_http_set_headers;
        for (i = 0; set[i].name.len; i++) {
            if (rp_strcasecmp(value[1].data, set[i].name.data) != 0) {
                continue;
            }

            hv->offset = set[i].offset;
            hv->handler = set[i].handler;

            break;
        }
    }

    if (value[2].len == 0) {
        rp_memzero(&hv->value, sizeof(rp_http_complex_value_t));

    } else {
        rp_memzero(&ccv, sizeof(rp_http_compile_complex_value_t));

        ccv.cf = cf;
        ccv.value = &value[2];
        ccv.complex_value = &hv->value;

        if (rp_http_compile_complex_value(&ccv) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    if (cf->args->nelts == 3) {
        return RP_CONF_OK;
    }

    if (rp_strcmp(value[3].data, "always") != 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[3]);
        return RP_CONF_ERROR;
    }

    hv->always = 1;

    return RP_CONF_OK;
}
