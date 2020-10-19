
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


#define RAP_HTTP_REALIP_XREALIP  0
#define RAP_HTTP_REALIP_XFWD     1
#define RAP_HTTP_REALIP_HEADER   2
#define RAP_HTTP_REALIP_PROXY    3


typedef struct {
    rap_array_t       *from;     /* array of rap_cidr_t */
    rap_uint_t         type;
    rap_uint_t         hash;
    rap_str_t          header;
    rap_flag_t         recursive;
} rap_http_realip_loc_conf_t;


typedef struct {
    rap_connection_t  *connection;
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    rap_str_t          addr_text;
} rap_http_realip_ctx_t;


static rap_int_t rap_http_realip_handler(rap_http_request_t *r);
static rap_int_t rap_http_realip_set_addr(rap_http_request_t *r,
    rap_addr_t *addr);
static void rap_http_realip_cleanup(void *data);
static char *rap_http_realip_from(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_http_realip(rap_conf_t *cf, rap_command_t *cmd, void *conf);
static void *rap_http_realip_create_loc_conf(rap_conf_t *cf);
static char *rap_http_realip_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);
static rap_int_t rap_http_realip_add_variables(rap_conf_t *cf);
static rap_int_t rap_http_realip_init(rap_conf_t *cf);
static rap_http_realip_ctx_t *rap_http_realip_get_module_ctx(
    rap_http_request_t *r);


static rap_int_t rap_http_realip_remote_addr_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_realip_remote_port_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);


static rap_command_t  rap_http_realip_commands[] = {

    { rap_string("set_real_ip_from"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_realip_from,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("real_ip_header"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_http_realip,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("real_ip_recursive"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_realip_loc_conf_t, recursive),
      NULL },

      rap_null_command
};



static rap_http_module_t  rap_http_realip_module_ctx = {
    rap_http_realip_add_variables,         /* preconfiguration */
    rap_http_realip_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_realip_create_loc_conf,       /* create location configuration */
    rap_http_realip_merge_loc_conf         /* merge location configuration */
};


rap_module_t  rap_http_realip_module = {
    RAP_MODULE_V1,
    &rap_http_realip_module_ctx,           /* module context */
    rap_http_realip_commands,              /* module directives */
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


static rap_http_variable_t  rap_http_realip_vars[] = {

    { rap_string("realip_remote_addr"), NULL,
      rap_http_realip_remote_addr_variable, 0, 0, 0 },

    { rap_string("realip_remote_port"), NULL,
      rap_http_realip_remote_port_variable, 0, 0, 0 },

      rap_http_null_variable
};


static rap_int_t
rap_http_realip_handler(rap_http_request_t *r)
{
    u_char                      *p;
    size_t                       len;
    rap_str_t                   *value;
    rap_uint_t                   i, hash;
    rap_addr_t                   addr;
    rap_array_t                 *xfwd;
    rap_list_part_t             *part;
    rap_table_elt_t             *header;
    rap_connection_t            *c;
    rap_http_realip_ctx_t       *ctx;
    rap_http_realip_loc_conf_t  *rlcf;

    rlcf = rap_http_get_module_loc_conf(r, rap_http_realip_module);

    if (rlcf->from == NULL) {
        return RAP_DECLINED;
    }

    ctx = rap_http_realip_get_module_ctx(r);

    if (ctx) {
        return RAP_DECLINED;
    }

    switch (rlcf->type) {

    case RAP_HTTP_REALIP_XREALIP:

        if (r->headers_in.x_real_ip == NULL) {
            return RAP_DECLINED;
        }

        value = &r->headers_in.x_real_ip->value;
        xfwd = NULL;

        break;

    case RAP_HTTP_REALIP_XFWD:

        xfwd = &r->headers_in.x_forwarded_for;

        if (xfwd->elts == NULL) {
            return RAP_DECLINED;
        }

        value = NULL;

        break;

    case RAP_HTTP_REALIP_PROXY:

        if (r->connection->proxy_protocol == NULL) {
            return RAP_DECLINED;
        }

        value = &r->connection->proxy_protocol->src_addr;
        xfwd = NULL;

        break;

    default: /* RAP_HTTP_REALIP_HEADER */

        part = &r->headers_in.headers.part;
        header = part->elts;

        hash = rlcf->hash;
        len = rlcf->header.len;
        p = rlcf->header.data;

        for (i = 0; /* void */ ; i++) {

            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }

            if (hash == header[i].hash
                && len == header[i].key.len
                && rap_strncmp(p, header[i].lowcase_key, len) == 0)
            {
                value = &header[i].value;
                xfwd = NULL;

                goto found;
            }
        }

        return RAP_DECLINED;
    }

found:

    c = r->connection;

    addr.sockaddr = c->sockaddr;
    addr.socklen = c->socklen;
    /* addr.name = c->addr_text; */

    if (rap_http_get_forwarded_addr(r, &addr, xfwd, value, rlcf->from,
                                    rlcf->recursive)
        != RAP_DECLINED)
    {
        if (rlcf->type == RAP_HTTP_REALIP_PROXY) {
            rap_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);
        }

        return rap_http_realip_set_addr(r, &addr);
    }

    return RAP_DECLINED;
}


static rap_int_t
rap_http_realip_set_addr(rap_http_request_t *r, rap_addr_t *addr)
{
    size_t                  len;
    u_char                 *p;
    u_char                  text[RAP_SOCKADDR_STRLEN];
    rap_connection_t       *c;
    rap_pool_cleanup_t     *cln;
    rap_http_realip_ctx_t  *ctx;

    cln = rap_pool_cleanup_add(r->pool, sizeof(rap_http_realip_ctx_t));
    if (cln == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = cln->data;

    c = r->connection;

    len = rap_sock_ntop(addr->sockaddr, addr->socklen, text,
                        RAP_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = rap_pnalloc(c->pool, len);
    if (p == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rap_memcpy(p, text, len);

    cln->handler = rap_http_realip_cleanup;
    rap_http_set_ctx(r, ctx, rap_http_realip_module);

    ctx->connection = c;
    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return RAP_DECLINED;
}


static void
rap_http_realip_cleanup(void *data)
{
    rap_http_realip_ctx_t *ctx = data;

    rap_connection_t  *c;

    c = ctx->connection;

    c->sockaddr = ctx->sockaddr;
    c->socklen = ctx->socklen;
    c->addr_text = ctx->addr_text;
}


static char *
rap_http_realip_from(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_realip_loc_conf_t *rlcf = conf;

    rap_int_t             rc;
    rap_str_t            *value;
    rap_url_t             u;
    rap_cidr_t            c, *cidr;
    rap_uint_t            i;
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

    if (rlcf->from == NULL) {
        rlcf->from = rap_array_create(cf->pool, 2,
                                      sizeof(rap_cidr_t));
        if (rlcf->from == NULL) {
            return RAP_CONF_ERROR;
        }
    }

#if (RAP_HAVE_UNIX_DOMAIN)

    if (rap_strcmp(value[1].data, "unix:") == 0) {
        cidr = rap_array_push(rlcf->from);
        if (cidr == NULL) {
            return RAP_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return RAP_CONF_OK;
    }

#endif

    rc = rap_ptocidr(&value[1], &c);

    if (rc != RAP_ERROR) {
        if (rc == RAP_DONE) {
            rap_conf_log_error(RAP_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = rap_array_push(rlcf->from);
        if (cidr == NULL) {
            return RAP_CONF_ERROR;
        }

        *cidr = c;

        return RAP_CONF_OK;
    }

    rap_memzero(&u, sizeof(rap_url_t));
    u.host = value[1];

    if (rap_inet_resolve_host(cf->pool, &u) != RAP_OK) {
        if (u.err) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "%s in set_real_ip_from \"%V\"",
                               u.err, &u.host);
        }

        return RAP_CONF_ERROR;
    }

    cidr = rap_array_push_n(rlcf->from, u.naddrs);
    if (cidr == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(cidr, u.naddrs * sizeof(rap_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (RAP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            rap_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

    return RAP_CONF_OK;
}


static char *
rap_http_realip(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_realip_loc_conf_t *rlcf = conf;

    rap_str_t  *value;

    if (rlcf->type != RAP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rap_strcmp(value[1].data, "X-Real-IP") == 0) {
        rlcf->type = RAP_HTTP_REALIP_XREALIP;
        return RAP_CONF_OK;
    }

    if (rap_strcmp(value[1].data, "X-Forwarded-For") == 0) {
        rlcf->type = RAP_HTTP_REALIP_XFWD;
        return RAP_CONF_OK;
    }

    if (rap_strcmp(value[1].data, "proxy_protocol") == 0) {
        rlcf->type = RAP_HTTP_REALIP_PROXY;
        return RAP_CONF_OK;
    }

    rlcf->type = RAP_HTTP_REALIP_HEADER;
    rlcf->hash = rap_hash_strlow(value[1].data, value[1].data, value[1].len);
    rlcf->header = value[1];

    return RAP_CONF_OK;
}


static void *
rap_http_realip_create_loc_conf(rap_conf_t *cf)
{
    rap_http_realip_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_realip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->from = NULL;
     *     conf->hash = 0;
     *     conf->header = { 0, NULL };
     */

    conf->type = RAP_CONF_UNSET_UINT;
    conf->recursive = RAP_CONF_UNSET;

    return conf;
}


static char *
rap_http_realip_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_realip_loc_conf_t  *prev = parent;
    rap_http_realip_loc_conf_t  *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    rap_conf_merge_uint_value(conf->type, prev->type, RAP_HTTP_REALIP_XREALIP);
    rap_conf_merge_value(conf->recursive, prev->recursive, 0);

    if (conf->header.len == 0) {
        conf->hash = prev->hash;
        conf->header = prev->header;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_http_realip_add_variables(rap_conf_t *cf)
{
    rap_http_variable_t  *var, *v;

    for (v = rap_http_realip_vars; v->name.len; v++) {
        var = rap_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_realip_init(rap_conf_t *cf)
{
    rap_http_handler_pt        *h;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    h = rap_array_push(&cmcf->phases[RAP_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_realip_handler;

    h = rap_array_push(&cmcf->phases[RAP_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_http_realip_handler;

    return RAP_OK;
}


static rap_http_realip_ctx_t *
rap_http_realip_get_module_ctx(rap_http_request_t *r)
{
    rap_pool_cleanup_t     *cln;
    rap_http_realip_ctx_t  *ctx;

    ctx = rap_http_get_module_ctx(r, rap_http_realip_module);

    if (ctx == NULL && (r->internal || r->filter_finalize)) {

        /*
         * if module context was reset, the original address
         * can still be found in the cleanup handler
         */

        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == rap_http_realip_cleanup) {
                ctx = cln->data;
                break;
            }
        }
    }

    return ctx;
}


static rap_int_t
rap_http_realip_remote_addr_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_str_t              *addr_text;
    rap_http_realip_ctx_t  *ctx;

    ctx = rap_http_realip_get_module_ctx(r);

    addr_text = ctx ? &ctx->addr_text : &r->connection->addr_text;

    v->len = addr_text->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr_text->data;

    return RAP_OK;
}


static rap_int_t
rap_http_realip_remote_port_variable(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_uint_t              port;
    struct sockaddr        *sa;
    rap_http_realip_ctx_t  *ctx;

    ctx = rap_http_realip_get_module_ctx(r);

    sa = ctx ? ctx->sockaddr : r->connection->sockaddr;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rap_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    port = rap_inet_get_port(sa);

    if (port > 0 && port < 65536) {
        v->len = rap_sprintf(v->data, "%ui", port) - v->data;
    }

    return RAP_OK;
}
