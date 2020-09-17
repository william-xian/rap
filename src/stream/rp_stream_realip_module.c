
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


typedef struct {
    rp_array_t       *from;     /* array of rp_cidr_t */
} rp_stream_realip_srv_conf_t;


typedef struct {
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    rp_str_t          addr_text;
} rp_stream_realip_ctx_t;


static rp_int_t rp_stream_realip_handler(rp_stream_session_t *s);
static rp_int_t rp_stream_realip_set_addr(rp_stream_session_t *s,
    rp_addr_t *addr);
static char *rp_stream_realip_from(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static void *rp_stream_realip_create_srv_conf(rp_conf_t *cf);
static char *rp_stream_realip_merge_srv_conf(rp_conf_t *cf, void *parent,
    void *child);
static rp_int_t rp_stream_realip_add_variables(rp_conf_t *cf);
static rp_int_t rp_stream_realip_init(rp_conf_t *cf);


static rp_int_t rp_stream_realip_remote_addr_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_realip_remote_port_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);


static rp_command_t  rp_stream_realip_commands[] = {

    { rp_string("set_real_ip_from"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_stream_realip_from,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_realip_module_ctx = {
    rp_stream_realip_add_variables,       /* preconfiguration */
    rp_stream_realip_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_stream_realip_create_srv_conf,     /* create server configuration */
    rp_stream_realip_merge_srv_conf       /* merge server configuration */
};


rp_module_t  rp_stream_realip_module = {
    RP_MODULE_V1,
    &rp_stream_realip_module_ctx,         /* module context */
    rp_stream_realip_commands,            /* module directives */
    RP_STREAM_MODULE,                     /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_stream_variable_t  rp_stream_realip_vars[] = {

    { rp_string("realip_remote_addr"), NULL,
      rp_stream_realip_remote_addr_variable, 0, 0, 0 },

    { rp_string("realip_remote_port"), NULL,
      rp_stream_realip_remote_port_variable, 0, 0, 0 },

      rp_stream_null_variable
};


static rp_int_t
rp_stream_realip_handler(rp_stream_session_t *s)
{
    rp_addr_t                     addr;
    rp_connection_t              *c;
    rp_stream_realip_srv_conf_t  *rscf;

    rscf = rp_stream_get_module_srv_conf(s, rp_stream_realip_module);

    if (rscf->from == NULL) {
        return RP_DECLINED;
    }

    c = s->connection;

    if (c->proxy_protocol == NULL) {
        return RP_DECLINED;
    }

    if (rp_cidr_match(c->sockaddr, rscf->from) != RP_OK) {
        return RP_DECLINED;
    }

    if (rp_parse_addr(c->pool, &addr, c->proxy_protocol->src_addr.data,
                       c->proxy_protocol->src_addr.len)
        != RP_OK)
    {
        return RP_DECLINED;
    }

    rp_inet_set_port(addr.sockaddr, c->proxy_protocol->src_port);

    return rp_stream_realip_set_addr(s, &addr);
}


static rp_int_t
rp_stream_realip_set_addr(rp_stream_session_t *s, rp_addr_t *addr)
{
    size_t                    len;
    u_char                   *p;
    u_char                    text[RP_SOCKADDR_STRLEN];
    rp_connection_t         *c;
    rp_stream_realip_ctx_t  *ctx;

    c = s->connection;

    ctx = rp_palloc(c->pool, sizeof(rp_stream_realip_ctx_t));
    if (ctx == NULL) {
        return RP_ERROR;
    }

    len = rp_sock_ntop(addr->sockaddr, addr->socklen, text,
                        RP_SOCKADDR_STRLEN, 0);
    if (len == 0) {
        return RP_ERROR;
    }

    p = rp_pnalloc(c->pool, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(p, text, len);

    rp_stream_set_ctx(s, ctx, rp_stream_realip_module);

    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return RP_DECLINED;
}


static char *
rp_stream_realip_from(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_realip_srv_conf_t *rscf = conf;

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

    if (rscf->from == NULL) {
        rscf->from = rp_array_create(cf->pool, 2,
                                      sizeof(rp_cidr_t));
        if (rscf->from == NULL) {
            return RP_CONF_ERROR;
        }
    }

#if (RP_HAVE_UNIX_DOMAIN)

    if (rp_strcmp(value[1].data, "unix:") == 0) {
        cidr = rp_array_push(rscf->from);
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

        cidr = rp_array_push(rscf->from);
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

    cidr = rp_array_push_n(rscf->from, u.naddrs);
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


static void *
rp_stream_realip_create_srv_conf(rp_conf_t *cf)
{
    rp_stream_realip_srv_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_stream_realip_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->from = NULL;
     */

    return conf;
}


static char *
rp_stream_realip_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_stream_realip_srv_conf_t *prev = parent;
    rp_stream_realip_srv_conf_t *conf = child;

    if (conf->from == NULL) {
        conf->from = prev->from;
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_stream_realip_add_variables(rp_conf_t *cf)
{
    rp_stream_variable_t  *var, *v;

    for (v = rp_stream_realip_vars; v->name.len; v++) {
        var = rp_stream_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return RP_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_stream_realip_init(rp_conf_t *cf)
{
    rp_stream_handler_pt        *h;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    h = rp_array_push(&cmcf->phases[RP_STREAM_POST_ACCEPT_PHASE].handlers);
    if (h == NULL) {
        return RP_ERROR;
    }

    *h = rp_stream_realip_handler;

    return RP_OK;
}


static rp_int_t
rp_stream_realip_remote_addr_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_str_t                *addr_text;
    rp_stream_realip_ctx_t  *ctx;

    ctx = rp_stream_get_module_ctx(s, rp_stream_realip_module);

    addr_text = ctx ? &ctx->addr_text : &s->connection->addr_text;

    v->len = addr_text->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr_text->data;

    return RP_OK;
}


static rp_int_t
rp_stream_realip_remote_port_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_uint_t                port;
    struct sockaddr          *sa;
    rp_stream_realip_ctx_t  *ctx;

    ctx = rp_stream_get_module_ctx(s, rp_stream_realip_module);

    sa = ctx ? ctx->sockaddr : s->connection->sockaddr;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rp_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    port = rp_inet_get_port(sa);

    if (port > 0 && port < 65536) {
        v->len = rp_sprintf(v->data, "%ui", port) - v->data;
    }

    return RP_OK;
}
