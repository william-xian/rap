
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_USERID_OFF   0
#define RAP_HTTP_USERID_LOG   1
#define RAP_HTTP_USERID_V1    2
#define RAP_HTTP_USERID_ON    3

/* 31 Dec 2037 23:55:55 GMT */
#define RAP_HTTP_USERID_MAX_EXPIRES  2145916555


typedef struct {
    rap_uint_t  enable;

    rap_int_t   service;

    rap_str_t   name;
    rap_str_t   domain;
    rap_str_t   path;
    rap_str_t   p3p;

    time_t      expires;

    u_char      mark;
} rap_http_userid_conf_t;


typedef struct {
    uint32_t    uid_got[4];
    uint32_t    uid_set[4];
    rap_str_t   cookie;
    rap_uint_t  reset;
} rap_http_userid_ctx_t;


static rap_http_userid_ctx_t *rap_http_userid_get_uid(rap_http_request_t *r,
    rap_http_userid_conf_t *conf);
static rap_int_t rap_http_userid_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, rap_str_t *name, uint32_t *uid);
static rap_int_t rap_http_userid_set_uid(rap_http_request_t *r,
    rap_http_userid_ctx_t *ctx, rap_http_userid_conf_t *conf);
static rap_int_t rap_http_userid_create_uid(rap_http_request_t *r,
    rap_http_userid_ctx_t *ctx, rap_http_userid_conf_t *conf);

static rap_int_t rap_http_userid_add_variables(rap_conf_t *cf);
static rap_int_t rap_http_userid_init(rap_conf_t *cf);
static void *rap_http_userid_create_conf(rap_conf_t *cf);
static char *rap_http_userid_merge_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_http_userid_domain(rap_conf_t *cf, void *post, void *data);
static char *rap_http_userid_path(rap_conf_t *cf, void *post, void *data);
static char *rap_http_userid_expires(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_userid_p3p(rap_conf_t *cf, void *post, void *data);
static char *rap_http_userid_mark(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static rap_int_t rap_http_userid_init_worker(rap_cycle_t *cycle);



static uint32_t  start_value;
static uint32_t  sequencer_v1 = 1;
static uint32_t  sequencer_v2 = 0x03030302;


static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";


static rap_http_output_header_filter_pt  rap_http_next_header_filter;


static rap_conf_enum_t  rap_http_userid_state[] = {
    { rap_string("off"), RAP_HTTP_USERID_OFF },
    { rap_string("log"), RAP_HTTP_USERID_LOG },
    { rap_string("v1"), RAP_HTTP_USERID_V1 },
    { rap_string("on"), RAP_HTTP_USERID_ON },
    { rap_null_string, 0 }
};


static rap_conf_post_handler_pt  rap_http_userid_domain_p =
    rap_http_userid_domain;
static rap_conf_post_handler_pt  rap_http_userid_path_p = rap_http_userid_path;
static rap_conf_post_handler_pt  rap_http_userid_p3p_p = rap_http_userid_p3p;


static rap_command_t  rap_http_userid_commands[] = {

    { rap_string("userid"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_enum_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_userid_conf_t, enable),
      rap_http_userid_state },

    { rap_string("userid_service"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_userid_conf_t, service),
      NULL },

    { rap_string("userid_name"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_userid_conf_t, name),
      NULL },

    { rap_string("userid_domain"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_userid_conf_t, domain),
      &rap_http_userid_domain_p },

    { rap_string("userid_path"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_userid_conf_t, path),
      &rap_http_userid_path_p },

    { rap_string("userid_expires"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_userid_expires,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("userid_p3p"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_userid_conf_t, p3p),
      &rap_http_userid_p3p_p },

    { rap_string("userid_mark"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_userid_mark,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_userid_filter_module_ctx = {
    rap_http_userid_add_variables,         /* preconfiguration */
    rap_http_userid_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_userid_create_conf,           /* create location configuration */
    rap_http_userid_merge_conf             /* merge location configuration */
};


rap_module_t  rap_http_userid_filter_module = {
    RAP_MODULE_V1,
    &rap_http_userid_filter_module_ctx,    /* module context */
    rap_http_userid_commands,              /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    rap_http_userid_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_str_t   rap_http_userid_got = rap_string("uid_got");
static rap_str_t   rap_http_userid_set = rap_string("uid_set");
static rap_str_t   rap_http_userid_reset = rap_string("uid_reset");
static rap_uint_t  rap_http_userid_reset_index;


static rap_int_t
rap_http_userid_filter(rap_http_request_t *r)
{
    rap_http_userid_ctx_t   *ctx;
    rap_http_userid_conf_t  *conf;

    if (r != r->main) {
        return rap_http_next_header_filter(r);
    }

    conf = rap_http_get_module_loc_conf(r, rap_http_userid_filter_module);

    if (conf->enable < RAP_HTTP_USERID_V1) {
        return rap_http_next_header_filter(r);
    }

    ctx = rap_http_userid_get_uid(r, conf);

    if (ctx == NULL) {
        return RAP_ERROR;
    }

    if (rap_http_userid_set_uid(r, ctx, conf) == RAP_OK) {
        return rap_http_next_header_filter(r);
    }

    return RAP_ERROR;
}


static rap_int_t
rap_http_userid_got_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_userid_ctx_t   *ctx;
    rap_http_userid_conf_t  *conf;

    conf = rap_http_get_module_loc_conf(r->main, rap_http_userid_filter_module);

    if (conf->enable == RAP_HTTP_USERID_OFF) {
        v->not_found = 1;
        return RAP_OK;
    }

    ctx = rap_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return RAP_ERROR;
    }

    if (ctx->uid_got[3] != 0) {
        return rap_http_userid_variable(r->main, v, &conf->name, ctx->uid_got);
    }

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_userid_set_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_userid_ctx_t   *ctx;
    rap_http_userid_conf_t  *conf;

    conf = rap_http_get_module_loc_conf(r->main, rap_http_userid_filter_module);

    if (conf->enable < RAP_HTTP_USERID_V1) {
        v->not_found = 1;
        return RAP_OK;
    }

    ctx = rap_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return RAP_ERROR;
    }

    if (rap_http_userid_create_uid(r->main, ctx, conf) != RAP_OK) {
        return RAP_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    return rap_http_userid_variable(r->main, v, &conf->name, ctx->uid_set);
}


static rap_http_userid_ctx_t *
rap_http_userid_get_uid(rap_http_request_t *r, rap_http_userid_conf_t *conf)
{
    rap_int_t                n;
    rap_str_t                src, dst;
    rap_table_elt_t        **cookies;
    rap_http_userid_ctx_t   *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_userid_filter_module);

    if (ctx) {
        return ctx;
    }

    if (ctx == NULL) {
        ctx = rap_pcalloc(r->pool, sizeof(rap_http_userid_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        rap_http_set_ctx(r, ctx, rap_http_userid_filter_module);
    }

    n = rap_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->name,
                                          &ctx->cookie);
    if (n == RAP_DECLINED) {
        return ctx;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &ctx->cookie);

    if (ctx->cookie.len < 22) {
        cookies = r->headers_in.cookies.elts;
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "client sent too short userid cookie \"%V\"",
                      &cookies[n]->value);
        return ctx;
    }

    src = ctx->cookie;

    /*
     * we have to limit the encoded string to 22 characters because
     *  1) cookie may be marked by "userid_mark",
     *  2) and there are already the millions cookies with a garbage
     *     instead of the correct base64 trail "=="
     */

    src.len = 22;

    dst.data = (u_char *) ctx->uid_got;

    if (rap_decode_base64(&dst, &src) == RAP_ERROR) {
        cookies = r->headers_in.cookies.elts;
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "client sent invalid userid cookie \"%V\"",
                      &cookies[n]->value);
        return ctx;
    }

    rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid: %08XD%08XD%08XD%08XD",
                   ctx->uid_got[0], ctx->uid_got[1],
                   ctx->uid_got[2], ctx->uid_got[3]);

    return ctx;
}


static rap_int_t
rap_http_userid_set_uid(rap_http_request_t *r, rap_http_userid_ctx_t *ctx,
    rap_http_userid_conf_t *conf)
{
    u_char           *cookie, *p;
    size_t            len;
    rap_str_t         src, dst;
    rap_table_elt_t  *set_cookie, *p3p;

    if (rap_http_userid_create_uid(r, ctx, conf) != RAP_OK) {
        return RAP_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        return RAP_OK;
    }

    len = conf->name.len + 1 + rap_base64_encoded_length(16) + conf->path.len;

    if (conf->expires) {
        len += sizeof(expires) - 1 + 2;
    }

    if (conf->domain.len) {
        len += conf->domain.len;
    }

    cookie = rap_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return RAP_ERROR;
    }

    p = rap_copy(cookie, conf->name.data, conf->name.len);
    *p++ = '=';

    if (ctx->uid_got[3] == 0 || ctx->reset) {
        src.len = 16;
        src.data = (u_char *) ctx->uid_set;
        dst.data = p;

        rap_encode_base64(&dst, &src);

        p += dst.len;

        if (conf->mark) {
            *(p - 2) = conf->mark;
        }

    } else {
        p = rap_cpymem(p, ctx->cookie.data, 22);
        *p++ = conf->mark;
        *p++ = '=';
    }

    if (conf->expires == RAP_HTTP_USERID_MAX_EXPIRES) {
        p = rap_cpymem(p, expires, sizeof(expires) - 1);

    } else if (conf->expires) {
        p = rap_cpymem(p, expires, sizeof("; expires=") - 1);
        p = rap_http_cookie_time(p, rap_time() + conf->expires);
    }

    p = rap_copy(p, conf->domain.data, conf->domain.len);

    p = rap_copy(p, conf->path.data, conf->path.len);

    set_cookie = rap_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return RAP_ERROR;
    }

    set_cookie->hash = 1;
    rap_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &set_cookie->value);

    if (conf->p3p.len == 0) {
        return RAP_OK;
    }

    p3p = rap_list_push(&r->headers_out.headers);
    if (p3p == NULL) {
        return RAP_ERROR;
    }

    p3p->hash = 1;
    rap_str_set(&p3p->key, "P3P");
    p3p->value = conf->p3p;

    return RAP_OK;
}


static rap_int_t
rap_http_userid_create_uid(rap_http_request_t *r, rap_http_userid_ctx_t *ctx,
    rap_http_userid_conf_t *conf)
{
    rap_connection_t           *c;
    struct sockaddr_in         *sin;
    rap_http_variable_value_t  *vv;
#if (RAP_HAVE_INET6)
    u_char                     *p;
    struct sockaddr_in6        *sin6;
#endif

    if (ctx->uid_set[3] != 0) {
        return RAP_OK;
    }

    if (ctx->uid_got[3] != 0) {

        vv = rap_http_get_indexed_variable(r, rap_http_userid_reset_index);

        if (vv == NULL || vv->not_found) {
            return RAP_ERROR;
        }

        if (vv->len == 0 || (vv->len == 1 && vv->data[0] == '0')) {

            if (conf->mark == '\0'
                || (ctx->cookie.len > 23
                    && ctx->cookie.data[22] == conf->mark
                    && ctx->cookie.data[23] == '='))
            {
                return RAP_OK;
            }

            ctx->uid_set[0] = ctx->uid_got[0];
            ctx->uid_set[1] = ctx->uid_got[1];
            ctx->uid_set[2] = ctx->uid_got[2];
            ctx->uid_set[3] = ctx->uid_got[3];

            return RAP_OK;

        } else {
            ctx->reset = 1;

            if (vv->len == 3 && rap_strncmp(vv->data, "log", 3) == 0) {
                rap_log_error(RAP_LOG_NOTICE, r->connection->log, 0,
                        "userid cookie \"%V=%08XD%08XD%08XD%08XD\" was reset",
                        &conf->name, ctx->uid_got[0], ctx->uid_got[1],
                        ctx->uid_got[2], ctx->uid_got[3]);
            }
        }
    }

    /*
     * TODO: in the threaded mode the sequencers should be in TLS and their
     * ranges should be divided between threads
     */

    if (conf->enable == RAP_HTTP_USERID_V1) {
        if (conf->service == RAP_CONF_UNSET) {
            ctx->uid_set[0] = 0;
        } else {
            ctx->uid_set[0] = conf->service;
        }
        ctx->uid_set[1] = (uint32_t) rap_time();
        ctx->uid_set[2] = start_value;
        ctx->uid_set[3] = sequencer_v1;
        sequencer_v1 += 0x100;

    } else {
        if (conf->service == RAP_CONF_UNSET) {

            c = r->connection;

            if (rap_connection_local_sockaddr(c, NULL, 0) != RAP_OK) {
                return RAP_ERROR;
            }

            switch (c->local_sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

                p = (u_char *) &ctx->uid_set[0];

                *p++ = sin6->sin6_addr.s6_addr[12];
                *p++ = sin6->sin6_addr.s6_addr[13];
                *p++ = sin6->sin6_addr.s6_addr[14];
                *p = sin6->sin6_addr.s6_addr[15];

                break;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
            case AF_UNIX:
                ctx->uid_set[0] = 0;
                break;
#endif

            default: /* AF_INET */
                sin = (struct sockaddr_in *) c->local_sockaddr;
                ctx->uid_set[0] = sin->sin_addr.s_addr;
                break;
            }

        } else {
            ctx->uid_set[0] = htonl(conf->service);
        }

        ctx->uid_set[1] = htonl((uint32_t) rap_time());
        ctx->uid_set[2] = htonl(start_value);
        ctx->uid_set[3] = htonl(sequencer_v2);
        sequencer_v2 += 0x100;
        if (sequencer_v2 < 0x03030302) {
            sequencer_v2 = 0x03030302;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_userid_variable(rap_http_request_t *r, rap_http_variable_value_t *v,
    rap_str_t *name, uint32_t *uid)
{
    v->len = name->len + sizeof("=00001111222233334444555566667777") - 1;
    v->data = rap_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    rap_sprintf(v->data, "%V=%08XD%08XD%08XD%08XD",
                name, uid[0], uid[1], uid[2], uid[3]);

    return RAP_OK;
}


static rap_int_t
rap_http_userid_reset_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    *v = rap_http_variable_null_value;

    return RAP_OK;
}


static rap_int_t
rap_http_userid_add_variables(rap_conf_t *cf)
{
    rap_int_t             n;
    rap_http_variable_t  *var;

    var = rap_http_add_variable(cf, &rap_http_userid_got, 0);
    if (var == NULL) {
        return RAP_ERROR;
    }

    var->get_handler = rap_http_userid_got_variable;

    var = rap_http_add_variable(cf, &rap_http_userid_set, 0);
    if (var == NULL) {
        return RAP_ERROR;
    }

    var->get_handler = rap_http_userid_set_variable;

    var = rap_http_add_variable(cf, &rap_http_userid_reset,
                                RAP_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return RAP_ERROR;
    }

    var->get_handler = rap_http_userid_reset_variable;

    n = rap_http_get_variable_index(cf, &rap_http_userid_reset);
    if (n == RAP_ERROR) {
        return RAP_ERROR;
    }

    rap_http_userid_reset_index = n;

    return RAP_OK;
}


static void *
rap_http_userid_create_conf(rap_conf_t *cf)
{
    rap_http_userid_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_userid_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->name = { 0, NULL };
     *     conf->domain = { 0, NULL };
     *     conf->path = { 0, NULL };
     *     conf->p3p = { 0, NULL };
     */

    conf->enable = RAP_CONF_UNSET_UINT;
    conf->service = RAP_CONF_UNSET;
    conf->expires = RAP_CONF_UNSET;
    conf->mark = (u_char) '\xFF';

    return conf;
}


static char *
rap_http_userid_merge_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_userid_conf_t *prev = parent;
    rap_http_userid_conf_t *conf = child;

    rap_conf_merge_uint_value(conf->enable, prev->enable,
                              RAP_HTTP_USERID_OFF);

    rap_conf_merge_str_value(conf->name, prev->name, "uid");
    rap_conf_merge_str_value(conf->domain, prev->domain, "");
    rap_conf_merge_str_value(conf->path, prev->path, "; path=/");
    rap_conf_merge_str_value(conf->p3p, prev->p3p, "");

    rap_conf_merge_value(conf->service, prev->service, RAP_CONF_UNSET);
    rap_conf_merge_sec_value(conf->expires, prev->expires, 0);

    if (conf->mark == (u_char) '\xFF') {
        if (prev->mark == (u_char) '\xFF') {
            conf->mark = '\0';
        } else {
            conf->mark = prev->mark;
        }
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_userid_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_userid_filter;

    return RAP_OK;
}


static char *
rap_http_userid_domain(rap_conf_t *cf, void *post, void *data)
{
    rap_str_t  *domain = data;

    u_char  *p, *new;

    if (rap_strcmp(domain->data, "none") == 0) {
        rap_str_set(domain, "");
        return RAP_CONF_OK;
    }

    new = rap_pnalloc(cf->pool, sizeof("; domain=") - 1 + domain->len);
    if (new == NULL) {
        return RAP_CONF_ERROR;
    }

    p = rap_cpymem(new, "; domain=", sizeof("; domain=") - 1);
    rap_memcpy(p, domain->data, domain->len);

    domain->len += sizeof("; domain=") - 1;
    domain->data = new;

    return RAP_CONF_OK;
}


static char *
rap_http_userid_path(rap_conf_t *cf, void *post, void *data)
{
    rap_str_t  *path = data;

    u_char  *p, *new;

    new = rap_pnalloc(cf->pool, sizeof("; path=") - 1 + path->len);
    if (new == NULL) {
        return RAP_CONF_ERROR;
    }

    p = rap_cpymem(new, "; path=", sizeof("; path=") - 1);
    rap_memcpy(p, path->data, path->len);

    path->len += sizeof("; path=") - 1;
    path->data = new;

    return RAP_CONF_OK;
}


static char *
rap_http_userid_expires(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_userid_conf_t *ucf = conf;

    rap_str_t  *value;

    if (ucf->expires != RAP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "max") == 0) {
        ucf->expires = RAP_HTTP_USERID_MAX_EXPIRES;
        return RAP_CONF_OK;
    }

    if (rap_strcmp(value[1].data, "off") == 0) {
        ucf->expires = 0;
        return RAP_CONF_OK;
    }

    ucf->expires = rap_parse_time(&value[1], 1);
    if (ucf->expires == (time_t) RAP_ERROR) {
        return "invalid value";
    }

    return RAP_CONF_OK;
}


static char *
rap_http_userid_p3p(rap_conf_t *cf, void *post, void *data)
{
    rap_str_t  *p3p = data;

    if (rap_strcmp(p3p->data, "none") == 0) {
        rap_str_set(p3p, "");
    }

    return RAP_CONF_OK;
}


static char *
rap_http_userid_mark(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_userid_conf_t *ucf = conf;

    rap_str_t  *value;

    if (ucf->mark != (u_char) '\xFF') {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "off") == 0) {
        ucf->mark = '\0';
        return RAP_CONF_OK;
    }

    if (value[1].len != 1
        || !((value[1].data[0] >= '0' && value[1].data[0] <= '9')
              || (value[1].data[0] >= 'A' && value[1].data[0] <= 'Z')
              || (value[1].data[0] >= 'a' && value[1].data[0] <= 'z')
              || value[1].data[0] == '='))
    {
        return "value must be \"off\" or a single letter, digit or \"=\"";
    }

    ucf->mark = value[1].data[0];

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_userid_init_worker(rap_cycle_t *cycle)
{
    struct timeval  tp;

    rap_gettimeofday(&tp);

    /* use the most significant usec part that fits to 16 bits */
    start_value = (((uint32_t) tp.tv_usec / 20) << 16) | rap_pid;

    return RAP_OK;
}
