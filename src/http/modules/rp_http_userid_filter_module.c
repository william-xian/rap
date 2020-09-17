
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_USERID_OFF   0
#define RP_HTTP_USERID_LOG   1
#define RP_HTTP_USERID_V1    2
#define RP_HTTP_USERID_ON    3

/* 31 Dec 2037 23:55:55 GMT */
#define RP_HTTP_USERID_MAX_EXPIRES  2145916555


typedef struct {
    rp_uint_t  enable;

    rp_int_t   service;

    rp_str_t   name;
    rp_str_t   domain;
    rp_str_t   path;
    rp_str_t   p3p;

    time_t      expires;

    u_char      mark;
} rp_http_userid_conf_t;


typedef struct {
    uint32_t    uid_got[4];
    uint32_t    uid_set[4];
    rp_str_t   cookie;
    rp_uint_t  reset;
} rp_http_userid_ctx_t;


static rp_http_userid_ctx_t *rp_http_userid_get_uid(rp_http_request_t *r,
    rp_http_userid_conf_t *conf);
static rp_int_t rp_http_userid_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, rp_str_t *name, uint32_t *uid);
static rp_int_t rp_http_userid_set_uid(rp_http_request_t *r,
    rp_http_userid_ctx_t *ctx, rp_http_userid_conf_t *conf);
static rp_int_t rp_http_userid_create_uid(rp_http_request_t *r,
    rp_http_userid_ctx_t *ctx, rp_http_userid_conf_t *conf);

static rp_int_t rp_http_userid_add_variables(rp_conf_t *cf);
static rp_int_t rp_http_userid_init(rp_conf_t *cf);
static void *rp_http_userid_create_conf(rp_conf_t *cf);
static char *rp_http_userid_merge_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_http_userid_domain(rp_conf_t *cf, void *post, void *data);
static char *rp_http_userid_path(rp_conf_t *cf, void *post, void *data);
static char *rp_http_userid_expires(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_userid_p3p(rp_conf_t *cf, void *post, void *data);
static char *rp_http_userid_mark(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static rp_int_t rp_http_userid_init_worker(rp_cycle_t *cycle);



static uint32_t  start_value;
static uint32_t  sequencer_v1 = 1;
static uint32_t  sequencer_v2 = 0x03030302;


static u_char expires[] = "; expires=Thu, 31-Dec-37 23:55:55 GMT";


static rp_http_output_header_filter_pt  rp_http_next_header_filter;


static rp_conf_enum_t  rp_http_userid_state[] = {
    { rp_string("off"), RP_HTTP_USERID_OFF },
    { rp_string("log"), RP_HTTP_USERID_LOG },
    { rp_string("v1"), RP_HTTP_USERID_V1 },
    { rp_string("on"), RP_HTTP_USERID_ON },
    { rp_null_string, 0 }
};


static rp_conf_post_handler_pt  rp_http_userid_domain_p =
    rp_http_userid_domain;
static rp_conf_post_handler_pt  rp_http_userid_path_p = rp_http_userid_path;
static rp_conf_post_handler_pt  rp_http_userid_p3p_p = rp_http_userid_p3p;


static rp_command_t  rp_http_userid_commands[] = {

    { rp_string("userid"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_enum_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_userid_conf_t, enable),
      rp_http_userid_state },

    { rp_string("userid_service"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_userid_conf_t, service),
      NULL },

    { rp_string("userid_name"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_userid_conf_t, name),
      NULL },

    { rp_string("userid_domain"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_userid_conf_t, domain),
      &rp_http_userid_domain_p },

    { rp_string("userid_path"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_userid_conf_t, path),
      &rp_http_userid_path_p },

    { rp_string("userid_expires"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_userid_expires,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("userid_p3p"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_userid_conf_t, p3p),
      &rp_http_userid_p3p_p },

    { rp_string("userid_mark"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_userid_mark,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_userid_filter_module_ctx = {
    rp_http_userid_add_variables,         /* preconfiguration */
    rp_http_userid_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_userid_create_conf,           /* create location configuration */
    rp_http_userid_merge_conf             /* merge location configuration */
};


rp_module_t  rp_http_userid_filter_module = {
    RP_MODULE_V1,
    &rp_http_userid_filter_module_ctx,    /* module context */
    rp_http_userid_commands,              /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    rp_http_userid_init_worker,           /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_str_t   rp_http_userid_got = rp_string("uid_got");
static rp_str_t   rp_http_userid_set = rp_string("uid_set");
static rp_str_t   rp_http_userid_reset = rp_string("uid_reset");
static rp_uint_t  rp_http_userid_reset_index;


static rp_int_t
rp_http_userid_filter(rp_http_request_t *r)
{
    rp_http_userid_ctx_t   *ctx;
    rp_http_userid_conf_t  *conf;

    if (r != r->main) {
        return rp_http_next_header_filter(r);
    }

    conf = rp_http_get_module_loc_conf(r, rp_http_userid_filter_module);

    if (conf->enable < RP_HTTP_USERID_V1) {
        return rp_http_next_header_filter(r);
    }

    ctx = rp_http_userid_get_uid(r, conf);

    if (ctx == NULL) {
        return RP_ERROR;
    }

    if (rp_http_userid_set_uid(r, ctx, conf) == RP_OK) {
        return rp_http_next_header_filter(r);
    }

    return RP_ERROR;
}


static rp_int_t
rp_http_userid_got_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_http_userid_ctx_t   *ctx;
    rp_http_userid_conf_t  *conf;

    conf = rp_http_get_module_loc_conf(r->main, rp_http_userid_filter_module);

    if (conf->enable == RP_HTTP_USERID_OFF) {
        v->not_found = 1;
        return RP_OK;
    }

    ctx = rp_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return RP_ERROR;
    }

    if (ctx->uid_got[3] != 0) {
        return rp_http_userid_variable(r->main, v, &conf->name, ctx->uid_got);
    }

    v->not_found = 1;

    return RP_OK;
}


static rp_int_t
rp_http_userid_set_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_http_userid_ctx_t   *ctx;
    rp_http_userid_conf_t  *conf;

    conf = rp_http_get_module_loc_conf(r->main, rp_http_userid_filter_module);

    if (conf->enable < RP_HTTP_USERID_V1) {
        v->not_found = 1;
        return RP_OK;
    }

    ctx = rp_http_userid_get_uid(r->main, conf);

    if (ctx == NULL) {
        return RP_ERROR;
    }

    if (rp_http_userid_create_uid(r->main, ctx, conf) != RP_OK) {
        return RP_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    return rp_http_userid_variable(r->main, v, &conf->name, ctx->uid_set);
}


static rp_http_userid_ctx_t *
rp_http_userid_get_uid(rp_http_request_t *r, rp_http_userid_conf_t *conf)
{
    rp_int_t                n;
    rp_str_t                src, dst;
    rp_table_elt_t        **cookies;
    rp_http_userid_ctx_t   *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_userid_filter_module);

    if (ctx) {
        return ctx;
    }

    if (ctx == NULL) {
        ctx = rp_pcalloc(r->pool, sizeof(rp_http_userid_ctx_t));
        if (ctx == NULL) {
            return NULL;
        }

        rp_http_set_ctx(r, ctx, rp_http_userid_filter_module);
    }

    n = rp_http_parse_multi_header_lines(&r->headers_in.cookies, &conf->name,
                                          &ctx->cookie);
    if (n == RP_DECLINED) {
        return ctx;
    }

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &ctx->cookie);

    if (ctx->cookie.len < 22) {
        cookies = r->headers_in.cookies.elts;
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
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

    if (rp_decode_base64(&dst, &src) == RP_ERROR) {
        cookies = r->headers_in.cookies.elts;
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "client sent invalid userid cookie \"%V\"",
                      &cookies[n]->value);
        return ctx;
    }

    rp_log_debug4(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid: %08XD%08XD%08XD%08XD",
                   ctx->uid_got[0], ctx->uid_got[1],
                   ctx->uid_got[2], ctx->uid_got[3]);

    return ctx;
}


static rp_int_t
rp_http_userid_set_uid(rp_http_request_t *r, rp_http_userid_ctx_t *ctx,
    rp_http_userid_conf_t *conf)
{
    u_char           *cookie, *p;
    size_t            len;
    rp_str_t         src, dst;
    rp_table_elt_t  *set_cookie, *p3p;

    if (rp_http_userid_create_uid(r, ctx, conf) != RP_OK) {
        return RP_ERROR;
    }

    if (ctx->uid_set[3] == 0) {
        return RP_OK;
    }

    len = conf->name.len + 1 + rp_base64_encoded_length(16) + conf->path.len;

    if (conf->expires) {
        len += sizeof(expires) - 1 + 2;
    }

    if (conf->domain.len) {
        len += conf->domain.len;
    }

    cookie = rp_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return RP_ERROR;
    }

    p = rp_copy(cookie, conf->name.data, conf->name.len);
    *p++ = '=';

    if (ctx->uid_got[3] == 0 || ctx->reset) {
        src.len = 16;
        src.data = (u_char *) ctx->uid_set;
        dst.data = p;

        rp_encode_base64(&dst, &src);

        p += dst.len;

        if (conf->mark) {
            *(p - 2) = conf->mark;
        }

    } else {
        p = rp_cpymem(p, ctx->cookie.data, 22);
        *p++ = conf->mark;
        *p++ = '=';
    }

    if (conf->expires == RP_HTTP_USERID_MAX_EXPIRES) {
        p = rp_cpymem(p, expires, sizeof(expires) - 1);

    } else if (conf->expires) {
        p = rp_cpymem(p, expires, sizeof("; expires=") - 1);
        p = rp_http_cookie_time(p, rp_time() + conf->expires);
    }

    p = rp_copy(p, conf->domain.data, conf->domain.len);

    p = rp_copy(p, conf->path.data, conf->path.len);

    set_cookie = rp_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return RP_ERROR;
    }

    set_cookie->hash = 1;
    rp_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = p - cookie;
    set_cookie->value.data = cookie;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "uid cookie: \"%V\"", &set_cookie->value);

    if (conf->p3p.len == 0) {
        return RP_OK;
    }

    p3p = rp_list_push(&r->headers_out.headers);
    if (p3p == NULL) {
        return RP_ERROR;
    }

    p3p->hash = 1;
    rp_str_set(&p3p->key, "P3P");
    p3p->value = conf->p3p;

    return RP_OK;
}


static rp_int_t
rp_http_userid_create_uid(rp_http_request_t *r, rp_http_userid_ctx_t *ctx,
    rp_http_userid_conf_t *conf)
{
    rp_connection_t           *c;
    struct sockaddr_in         *sin;
    rp_http_variable_value_t  *vv;
#if (RP_HAVE_INET6)
    u_char                     *p;
    struct sockaddr_in6        *sin6;
#endif

    if (ctx->uid_set[3] != 0) {
        return RP_OK;
    }

    if (ctx->uid_got[3] != 0) {

        vv = rp_http_get_indexed_variable(r, rp_http_userid_reset_index);

        if (vv == NULL || vv->not_found) {
            return RP_ERROR;
        }

        if (vv->len == 0 || (vv->len == 1 && vv->data[0] == '0')) {

            if (conf->mark == '\0'
                || (ctx->cookie.len > 23
                    && ctx->cookie.data[22] == conf->mark
                    && ctx->cookie.data[23] == '='))
            {
                return RP_OK;
            }

            ctx->uid_set[0] = ctx->uid_got[0];
            ctx->uid_set[1] = ctx->uid_got[1];
            ctx->uid_set[2] = ctx->uid_got[2];
            ctx->uid_set[3] = ctx->uid_got[3];

            return RP_OK;

        } else {
            ctx->reset = 1;

            if (vv->len == 3 && rp_strncmp(vv->data, "log", 3) == 0) {
                rp_log_error(RP_LOG_NOTICE, r->connection->log, 0,
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

    if (conf->enable == RP_HTTP_USERID_V1) {
        if (conf->service == RP_CONF_UNSET) {
            ctx->uid_set[0] = 0;
        } else {
            ctx->uid_set[0] = conf->service;
        }
        ctx->uid_set[1] = (uint32_t) rp_time();
        ctx->uid_set[2] = start_value;
        ctx->uid_set[3] = sequencer_v1;
        sequencer_v1 += 0x100;

    } else {
        if (conf->service == RP_CONF_UNSET) {

            c = r->connection;

            if (rp_connection_local_sockaddr(c, NULL, 0) != RP_OK) {
                return RP_ERROR;
            }

            switch (c->local_sockaddr->sa_family) {

#if (RP_HAVE_INET6)
            case AF_INET6:
                sin6 = (struct sockaddr_in6 *) c->local_sockaddr;

                p = (u_char *) &ctx->uid_set[0];

                *p++ = sin6->sin6_addr.s6_addr[12];
                *p++ = sin6->sin6_addr.s6_addr[13];
                *p++ = sin6->sin6_addr.s6_addr[14];
                *p = sin6->sin6_addr.s6_addr[15];

                break;
#endif

#if (RP_HAVE_UNIX_DOMAIN)
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

        ctx->uid_set[1] = htonl((uint32_t) rp_time());
        ctx->uid_set[2] = htonl(start_value);
        ctx->uid_set[3] = htonl(sequencer_v2);
        sequencer_v2 += 0x100;
        if (sequencer_v2 < 0x03030302) {
            sequencer_v2 = 0x03030302;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_http_userid_variable(rp_http_request_t *r, rp_http_variable_value_t *v,
    rp_str_t *name, uint32_t *uid)
{
    v->len = name->len + sizeof("=00001111222233334444555566667777") - 1;
    v->data = rp_pnalloc(r->pool, v->len);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    rp_sprintf(v->data, "%V=%08XD%08XD%08XD%08XD",
                name, uid[0], uid[1], uid[2], uid[3]);

    return RP_OK;
}


static rp_int_t
rp_http_userid_reset_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    *v = rp_http_variable_null_value;

    return RP_OK;
}


static rp_int_t
rp_http_userid_add_variables(rp_conf_t *cf)
{
    rp_int_t             n;
    rp_http_variable_t  *var;

    var = rp_http_add_variable(cf, &rp_http_userid_got, 0);
    if (var == NULL) {
        return RP_ERROR;
    }

    var->get_handler = rp_http_userid_got_variable;

    var = rp_http_add_variable(cf, &rp_http_userid_set, 0);
    if (var == NULL) {
        return RP_ERROR;
    }

    var->get_handler = rp_http_userid_set_variable;

    var = rp_http_add_variable(cf, &rp_http_userid_reset,
                                RP_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return RP_ERROR;
    }

    var->get_handler = rp_http_userid_reset_variable;

    n = rp_http_get_variable_index(cf, &rp_http_userid_reset);
    if (n == RP_ERROR) {
        return RP_ERROR;
    }

    rp_http_userid_reset_index = n;

    return RP_OK;
}


static void *
rp_http_userid_create_conf(rp_conf_t *cf)
{
    rp_http_userid_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_userid_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->name = { 0, NULL };
     *     conf->domain = { 0, NULL };
     *     conf->path = { 0, NULL };
     *     conf->p3p = { 0, NULL };
     */

    conf->enable = RP_CONF_UNSET_UINT;
    conf->service = RP_CONF_UNSET;
    conf->expires = RP_CONF_UNSET;
    conf->mark = (u_char) '\xFF';

    return conf;
}


static char *
rp_http_userid_merge_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_userid_conf_t *prev = parent;
    rp_http_userid_conf_t *conf = child;

    rp_conf_merge_uint_value(conf->enable, prev->enable,
                              RP_HTTP_USERID_OFF);

    rp_conf_merge_str_value(conf->name, prev->name, "uid");
    rp_conf_merge_str_value(conf->domain, prev->domain, "");
    rp_conf_merge_str_value(conf->path, prev->path, "; path=/");
    rp_conf_merge_str_value(conf->p3p, prev->p3p, "");

    rp_conf_merge_value(conf->service, prev->service, RP_CONF_UNSET);
    rp_conf_merge_sec_value(conf->expires, prev->expires, 0);

    if (conf->mark == (u_char) '\xFF') {
        if (prev->mark == (u_char) '\xFF') {
            conf->mark = '\0';
        } else {
            conf->mark = prev->mark;
        }
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_userid_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_userid_filter;

    return RP_OK;
}


static char *
rp_http_userid_domain(rp_conf_t *cf, void *post, void *data)
{
    rp_str_t  *domain = data;

    u_char  *p, *new;

    if (rp_strcmp(domain->data, "none") == 0) {
        rp_str_set(domain, "");
        return RP_CONF_OK;
    }

    new = rp_pnalloc(cf->pool, sizeof("; domain=") - 1 + domain->len);
    if (new == NULL) {
        return RP_CONF_ERROR;
    }

    p = rp_cpymem(new, "; domain=", sizeof("; domain=") - 1);
    rp_memcpy(p, domain->data, domain->len);

    domain->len += sizeof("; domain=") - 1;
    domain->data = new;

    return RP_CONF_OK;
}


static char *
rp_http_userid_path(rp_conf_t *cf, void *post, void *data)
{
    rp_str_t  *path = data;

    u_char  *p, *new;

    new = rp_pnalloc(cf->pool, sizeof("; path=") - 1 + path->len);
    if (new == NULL) {
        return RP_CONF_ERROR;
    }

    p = rp_cpymem(new, "; path=", sizeof("; path=") - 1);
    rp_memcpy(p, path->data, path->len);

    path->len += sizeof("; path=") - 1;
    path->data = new;

    return RP_CONF_OK;
}


static char *
rp_http_userid_expires(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_userid_conf_t *ucf = conf;

    rp_str_t  *value;

    if (ucf->expires != RP_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "max") == 0) {
        ucf->expires = RP_HTTP_USERID_MAX_EXPIRES;
        return RP_CONF_OK;
    }

    if (rp_strcmp(value[1].data, "off") == 0) {
        ucf->expires = 0;
        return RP_CONF_OK;
    }

    ucf->expires = rp_parse_time(&value[1], 1);
    if (ucf->expires == (time_t) RP_ERROR) {
        return "invalid value";
    }

    return RP_CONF_OK;
}


static char *
rp_http_userid_p3p(rp_conf_t *cf, void *post, void *data)
{
    rp_str_t  *p3p = data;

    if (rp_strcmp(p3p->data, "none") == 0) {
        rp_str_set(p3p, "");
    }

    return RP_CONF_OK;
}


static char *
rp_http_userid_mark(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_userid_conf_t *ucf = conf;

    rp_str_t  *value;

    if (ucf->mark != (u_char) '\xFF') {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "off") == 0) {
        ucf->mark = '\0';
        return RP_CONF_OK;
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

    return RP_CONF_OK;
}


static rp_int_t
rp_http_userid_init_worker(rp_cycle_t *cycle)
{
    struct timeval  tp;

    rp_gettimeofday(&tp);

    /* use the most significant usec part that fits to 16 bits */
    start_value = (((uint32_t) tp.tv_usec / 20) << 16) | rp_pid;

    return RP_OK;
}
