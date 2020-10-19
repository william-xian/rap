
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


typedef struct {
    rap_array_t       *from;     /* array of rap_cidr_t */
} rap_stream_realip_srv_conf_t;


typedef struct {
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    rap_str_t          addr_text;
} rap_stream_realip_ctx_t;


static rap_int_t rap_stream_realip_handler(rap_stream_session_t *s);
static rap_int_t rap_stream_realip_set_addr(rap_stream_session_t *s,
    rap_addr_t *addr);
static char *rap_stream_realip_from(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static void *rap_stream_realip_create_srv_conf(rap_conf_t *cf);
static char *rap_stream_realip_merge_srv_conf(rap_conf_t *cf, void *parent,
    void *child);
static rap_int_t rap_stream_realip_add_variables(rap_conf_t *cf);
static rap_int_t rap_stream_realip_init(rap_conf_t *cf);


static rap_int_t rap_stream_realip_remote_addr_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_realip_remote_port_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);


static rap_command_t  rap_stream_realip_commands[] = {

    { rap_string("set_real_ip_from"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_stream_realip_from,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_stream_module_t  rap_stream_realip_module_ctx = {
    rap_stream_realip_add_variables,       /* preconfiguration */
    rap_stream_realip_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_stream_realip_create_srv_conf,     /* create server configuration */
    rap_stream_realip_merge_srv_conf       /* merge server configuration */
};


rap_module_t  rap_stream_realip_module = {
    RAP_MODULE_V1,
    &rap_stream_realip_module_ctx,         /* module context */
    rap_stream_realip_commands,            /* module directives */
    RAP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_stream_variable_t  rap_stream_realip_vars[] = {

    { rap_string("realip_remote_addr"), NULL,
      rap_stream_realip_remote_addr_variable, 0, 0, 0 },

    { rap_string("realip_remote_port"), NULL,
      rap_stream_realip_remote_port_variable, 0, 0, 0 },

      rap_stream_null_variable
};


static rap_int_t
rap_stream_realip_handler(rap_stream_session_t *s)
{
    rap_addr_t                     addr;
    rap_connection_t              *c;
    rap_stream_realip_srv_conf_t  *rscf;

    rscf = rap_stream_get_module_srv_conf(s, rap_stream_realip_module);

    if (rscf->from == NULL) {
        return RAP_DECLINED;
    }

    c = s->connection;

    if (c->proxy_protocol == NULL) {
        return RAP_DECLINED;
    }

    if (rap_cidr_match(c->sockaddr, rscf->from) != RAP_OK) {
        return RAP_DECLINED;
    }

    if (rap_parse_addr(c->pool, &addr, c->proxy_protocol->src_addr.data,
                       c->proxy_protocol->src_addr.len)
        != RAP_OK)
    {
        return RAP_DECLINED;
    }

    rap_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);

    return rap_stream_realip_set_addr(s, &addr);
}


static rap_int_t
rap_stream_realip_set_addr(rap_stream_session_t *s, rap_addr_t *addr)
{
    size_t                    len;
    u_char                   *p;
    u_char                    text[RAP_SOCKADDR_STRLEN];
    rap_connection_t         *c;
    rap_stream_realip_ctx_t  *ctx;

    c = s->connection;

    ctx = rap_palloc(c->pool, sizeof(rap_stream_realip_ctx_t));
    if (ctx == NULL) {
        return RAP_ERROR;
    }

    len = rap_sock_ntop(addr->sockaddr, addr->socklen, text,
                        RAP_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return RAP_ERROR;
    }

    p = rap_pnalloc(c->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(p, text, len);

    rap_stream_set_ctx(s, ctx, rap_stream_realip_module);

    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return RAP_DECLINED;
}


static char *
rap_stream_realip_from(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_realip_srv_conf_t *rscf = conf;

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

    if (rscf->from == NULL) {
        rscf->from = rap_array_create(cf->pool, 2,
                                      sizeof(rap_cidr_t));
        if (rscf->from == NULL) {
            return RAP_CONF_ERROR;
        }
    }

#if (RAP_HAVE_UNIX_DOMAIN)

    if (rap_strcmp(value[1].data, "unix:") == 0) {
        cidr = rap_array_push(rscf->from);
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

        cidr = rap_array_push(rscf->from);
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

    cidr = rap_array_push_n(rscf->from, u.naddrs);
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


static void *
rap_stream_realip_create_srv_conf(rap_conf_t *cf)
{
    rap_stream_realip_srv_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_stream_realip_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->from = NULL;
     */

    return conf;
}


static char *
rap_stream_realip_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_stream_realip_srv_conf_t *prev = parent;
    rap_stream_realip_srv_conf_t *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    return RAP_CONF_OK;
}


static rap_int_t
rap_stream_realip_add_variables(rap_conf_t *cf)
{
    rap_stream_variable_t  *var, *v;

    for (v = rap_stream_realip_vars; v->name.len; v++) {
        var = rap_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RAP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_stream_realip_init(rap_conf_t *cf)
{
    rap_stream_handler_pt        *h;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);

    h = rap_array_push(&cmcf->phases[RAP_STREAM_POST_ACCEPT_PHASE].handlers);
    if (h == NULL) {
        return RAP_ERROR;
    }

    *h = rap_stream_realip_handler;

    return RAP_OK;
}


static rap_int_t
rap_stream_realip_remote_addr_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_str_t                *addr_text;
    rap_stream_realip_ctx_t  *ctx;

    ctx = rap_stream_get_module_ctx(s, rap_stream_realip_module);

    addr_text = ctx ? &ctx->addr_text : &s->connection->addr_text;

    v->len = addr_text->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr_text->data;

    return RAP_OK;
}


static rap_int_t
rap_stream_realip_remote_port_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_uint_t                port;
    struct sockaddr          *sa;
    rap_stream_realip_ctx_t  *ctx;

    ctx = rap_stream_get_module_ctx(s, rap_stream_realip_module);

    sa = ctx ? ctx->sockaddr : s->connection->sockaddr;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rap_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    port = rap_inet_get_port(sa);

    if (port > 0 && port < 65536) {
        v->len = rap_sprintf(v->data, "%ui", port) - v->data;
    }

    return RAP_OK;
}
