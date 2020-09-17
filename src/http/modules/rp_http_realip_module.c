
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


#define RP_HTTP_REALIP_XREALIP  0
#define RP_HTTP_REALIP_XFWD     1
#define RP_HTTP_REALIP_HEADER   2
#define RP_HTTP_REALIP_PROXY    3


typedef struct {
    rp_array_t       *from;     /* array of rp_cidr_t */
    rp_uint_t         type;
    rp_uint_t         hash;
    rp_str_t          header;
    rp_flag_t         recursive;
} rp_http_realip_loc_conf_t;


typedef struct {
    rp_connection_t  *connection;
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    rp_str_t          addr_text;
} rp_http_realip_ctx_t;


static rp_int_t rp_http_realip_handler(rp_http_request_t *r);
static rp_int_t rp_http_realip_set_addr(rp_http_request_t *r,
    rp_addr_t *addr);
static void rp_http_realip_cleanup(void *data);
static char *rp_http_realip_from(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_http_realip(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static void *rp_http_realip_create_loc_conf(rp_conf_t *cf);
static char *rp_http_realip_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);
static rp_int_t rp_http_realip_add_variables(rp_conf_t *cf);
static rp_int_t rp_http_realip_init(rp_conf_t *cf);
static rp_http_realip_ctx_t *rp_http_realip_get_module_ctx(
    rp_http_request_t *r);


static rp_int_t rp_http_realip_remote_addr_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_realip_remote_port_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);


static rp_command_t  rp_http_realip_commands[] = {

    { rp_string("set_real_ip_from"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_realip_from,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("real_ip_header"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_http_realip,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("real_ip_recursive"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_realip_loc_conf_t, recursive),
      NULL },

      rp_null_command
};



static rp_http_module_t  rp_http_realip_module_ctx = {
    rp_http_realip_add_variables,         /* preconfiguration */
    rp_http_realip_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_realip_create_loc_conf,       /* create location configuration */
    rp_http_realip_merge_loc_conf         /* merge location configuration */
};


rp_module_t  rp_http_realip_module = {
    RP_MODULE_V1,
    &rp_http_realip_module_ctx,           /* module context */
    rp_http_realip_commands,              /* module directives */
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


static rp_http_variable_t  rp_http_realip_vars[] = {

    { rp_string("realip_remote_addr"), NULL,
      rp_http_realip_remote_addr_variable, 0, 0, 0 },

    { rp_string("realip_remote_port"), NULL,
      rp_http_realip_remote_port_variable, 0, 0, 0 },

      rp_http_null_variable
};


static rp_int_t
rp_http_realip_handler(rp_http_request_t *r)
{
    u_char                      *p;
    size_t                       len;
    rp_str_t                   *value;
    rp_uint_t                   i, hash;
    rp_addr_t                   addr;
    rp_array_t                 *xfwd;
    rp_list_part_t             *part;
    rp_table_elt_t             *header;
    rp_connection_t            *c;
    rp_http_realip_ctx_t       *ctx;
    rp_http_realip_loc_conf_t  *rlcf;

    rlcf = rp_http_get_module_loc_conf(r, rp_http_realip_module);

    if (rlcf->from == NULL) {
        return RP_DECLINED;
    }

    ctx = rp_http_realip_get_module_ctx(r);

    if (ctx) {
        return RP_DECLINED;
    }

    switch (rlcf->type) {

    case RP_HTTP_REALIP_XREALIP:

        if (r->headers_in.x_real_ip == NULL) {
            return RP_DECLINED;
        }

        value = &r->headers_in.x_real_ip->value;
        xfwd = NULL;

        break;

    case RP_HTTP_REALIP_XFWD:

        xfwd = &r->headers_in.x_forwarded_for;

        if (xfwd->elts == NULL) {
            return RP_DECLINED;
        }

        value = NULL;

        break;

    case RP_HTTP_REALIP_PROXY:

        if (r->connection->proxy_protocol == NULL) {
            return RP_DECLINED;
        }

        value = &r->connection->proxy_protocol->src_addr;
        xfwd = NULL;

        break;

    default: /* RP_HTTP_REALIP_HEADER */

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
                && rp_strncmp(p, header[i].lowcase_key, len) == 0)
            {
                value = &header[i].value;
                xfwd = NULL;

                goto found;
            }
        }

        return RP_DECLINED;
    }

found:

    c = r->connection;

    addr.sockaddr = c->sockaddr;
    addr.socklen = c->socklen;
    /* addr.name = c->addr_text; */

    if (rp_http_get_forwarded_addr(r, &addr, xfwd, value, rlcf->from,
                                    rlcf->recursive)
        != RP_DECLINED)
    {
        if (rlcf->type == RP_HTTP_REALIP_PROXY) {
            rp_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);
        }

        return rp_http_realip_set_addr(r, &addr);
    }

    return RP_DECLINED;
}


static rp_int_t
rp_http_realip_set_addr(rp_http_request_t *r, rp_addr_t *addr)
{
    size_t                  len;
    u_char                 *p;
    u_char                  text[RP_SOCKADDR_STRLEN];
    rp_connection_t       *c;
    rp_pool_cleanup_t     *cln;
    rp_http_realip_ctx_t  *ctx;

    cln = rp_pool_cleanup_add(r->pool, sizeof(rp_http_realip_ctx_t));
    if (cln == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = cln->data;

    c = r->connection;

    len = rp_sock_ntop(addr->sockaddr, addr->socklen, text,
                        RP_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = rp_pnalloc(c->pool, len);
    if (p == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    rp_memcpy(p, text, len);

    cln->handler = rp_http_realip_cleanup;
    rp_http_set_ctx(r, ctx, rp_http_realip_module);

    ctx->connection = c;
    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return RP_DECLINED;
}


static void
rp_http_realip_cleanup(void *data)
{
    rp_http_realip_ctx_t *ctx = data;

    rp_connection_t  *c;

    c = ctx->connection;

    c->sockaddr = ctx->sockaddr;
    c->socklen = ctx->socklen;
    c->addr_text = ctx->addr_text;
}


static char *
rp_http_realip_from(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_realip_loc_conf_t *rlcf = conf;

    rp_int_t             rc;
    rp_str_t            *value;
    rp_url_t             u;
    rp_cidr_t            c, *cidr;
    rp_uint_t            i;
    struct sockaddr_in   *sin;
#if (RP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

    if (rlcf->from == NULL) {
        rlcf->from = rp_array_create(cf->pool, 2,
                                      sizeof(rp_cidr_t));
        if (rlcf->from == NULL) {
            return RP_CONF_ERROR;
        }
    }

#if (RP_HAVE_UNIX_DOMAIN)

    if (rp_strcmp(value[1].data, "unix:") == 0) {
        cidr = rp_array_push(rlcf->from);
        if (cidr == NULL) {
            return RP_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return RP_CONF_OK;
    }

#endif

    rc = rp_ptocidr(&value[1], &c);

    if (rc != RP_ERROR) {
        if (rc == RP_DONE) {
            rp_conf_log_error(RP_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = rp_array_push(rlcf->from);
        if (cidr == NULL) {
            return RP_CONF_ERROR;
        }

        *cidr = c;

        return RP_CONF_OK;
    }

    rp_memzero(&u, sizeof(rp_url_t));
    u.host = value[1];

    if (rp_inet_resolve_host(cf->pool, &u) != RP_OK) {
        if (u.err) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "%s in set_real_ip_from \"%V\"",
                               u.err, &u.host);
        }

        return RP_CONF_ERROR;
    }

    cidr = rp_array_push_n(rlcf->from, u.naddrs);
    if (cidr == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(cidr, u.naddrs * sizeof(rp_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (RP_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            rp_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

    return RP_CONF_OK;
}


static char *
rp_http_realip(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_realip_loc_conf_t *rlcf = conf;

    rp_str_t  *value;

    if (rlcf->type != RP_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (rp_strcmp(value[1].data, "X-Real-IP") == 0) {
        rlcf->type = RP_HTTP_REALIP_XREALIP;
        return RP_CONF_OK;
    }

    if (rp_strcmp(value[1].data, "X-Forwarded-For") == 0) {
        rlcf->type = RP_HTTP_REALIP_XFWD;
        return RP_CONF_OK;
    }

    if (rp_strcmp(value[1].data, "proxy_protocol") == 0) {
        rlcf->type = RP_HTTP_REALIP_PROXY;
        return RP_CONF_OK;
    }

    rlcf->type = RP_HTTP_REALIP_HEADER;
    rlcf->hash = rp_hash_strlow(value[1].data, value[1].data, value[1].len);
    rlcf->header = value[1];

    return RP_CONF_OK;
}


static void *
rp_http_realip_create_loc_conf(rp_conf_t *cf)
{
    rp_http_realip_loc_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_realip_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->from = NULL;
     *     conf->hash = 0;
     *     conf->header = { 0, NULL };
     */

    conf->type = RP_CONF_UNSET_UINT;
    conf->recursive = RP_CONF_UNSET;

    return conf;
}


static char *
rp_http_realip_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_realip_loc_conf_t  *prev = parent;
    rp_http_realip_loc_conf_t  *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    rp_conf_merge_uint_value(conf->type, prev->type, RP_HTTP_REALIP_XREALIP);
    rp_conf_merge_value(conf->recursive, prev->recursive, 0);

    if (conf->header.len == 0) {
        conf->hash = prev->hash;
        conf->header = prev->header;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_http_realip_add_variables(rp_conf_t *cf)
{
    rp_http_variable_t  *var, *v;

    for (v = rp_http_realip_vars; v->name.len; v++) {
        var = rp_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_http_realip_init(rp_conf_t *cf)
{
    rp_http_handler_pt        *h;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    h = rp_array_push(&cmcf->phases[RP_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_realip_handler;

    h = rp_array_push(&cmcf->phases[RP_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_http_realip_handler;

    return RP_OK;
}


static rp_http_realip_ctx_t *
rp_http_realip_get_module_ctx(rp_http_request_t *r)
{
    rp_pool_cleanup_t     *cln;
    rp_http_realip_ctx_t  *ctx;

    ctx = rp_http_get_module_ctx(r, rp_http_realip_module);

    if (ctx == NULL && (r->internal || r->filter_finalize)) {

        /*
         * if module context was reset, the original address
         * can still be found in the cleanup handler
         */

        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == rp_http_realip_cleanup) {
                ctx = cln->data;
                break;
            }
        }
    }

    return ctx;
}


static rp_int_t
rp_http_realip_remote_addr_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_str_t              *addr_text;
    rp_http_realip_ctx_t  *ctx;

    ctx = rp_http_realip_get_module_ctx(r);

    addr_text = ctx ? &ctx->addr_text : &r->connection->addr_text;

    v->len = addr_text->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr_text->data;

    return RP_OK;
}


static rp_int_t
rp_http_realip_remote_port_variable(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_uint_t              port;
    struct sockaddr        *sa;
    rp_http_realip_ctx_t  *ctx;

    ctx = rp_http_realip_get_module_ctx(r);

    sa = ctx ? ctx->sockaddr : r->connection->sockaddr;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rp_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    port = rp_inet_get_port(sa);

    if (port > 0 && port < 65536) {
        v->len = rp_sprintf(v->data, "%ui", port) - v->data;
    }

    return RP_OK;
}
