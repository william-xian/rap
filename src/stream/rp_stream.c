
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_stream.h>


static char *rp_stream_block(rp_conf_t *cf, rp_command_t *cmd, void *conf);
static rp_int_t rp_stream_init_phases(rp_conf_t *cf,
    rp_stream_core_main_conf_t *cmcf);
static rp_int_t rp_stream_init_phase_handlers(rp_conf_t *cf,
    rp_stream_core_main_conf_t *cmcf);
static rp_int_t rp_stream_add_ports(rp_conf_t *cf, rp_array_t *ports,
    rp_stream_listen_t *listen);
static char *rp_stream_optimize_servers(rp_conf_t *cf, rp_array_t *ports);
static rp_int_t rp_stream_add_addrs(rp_conf_t *cf, rp_stream_port_t *stport,
    rp_stream_conf_addr_t *addr);
#if (RP_HAVE_INET6)
static rp_int_t rp_stream_add_addrs6(rp_conf_t *cf,
    rp_stream_port_t *stport, rp_stream_conf_addr_t *addr);
#endif
static rp_int_t rp_stream_cmp_conf_addrs(const void *one, const void *two);


rp_uint_t  rp_stream_max_module;


rp_stream_filter_pt  rp_stream_top_filter;


static rp_command_t  rp_stream_commands[] = {

    { rp_string("stream"),
      RP_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_NOARGS,
      rp_stream_block,
      0,
      0,
      NULL },

      rp_null_command
};


static rp_core_module_t  rp_stream_module_ctx = {
    rp_string("stream"),
    NULL,
    NULL
};


rp_module_t  rp_stream_module = {
    RP_MODULE_V1,
    &rp_stream_module_ctx,                /* module context */
    rp_stream_commands,                   /* module directives */
    RP_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static char *
rp_stream_block(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char                          *rv;
    rp_uint_t                     i, m, mi, s;
    rp_conf_t                     pcf;
    rp_array_t                    ports;
    rp_stream_listen_t           *listen;
    rp_stream_module_t           *module;
    rp_stream_conf_ctx_t         *ctx;
    rp_stream_core_srv_conf_t   **cscfp;
    rp_stream_core_main_conf_t   *cmcf;

    if (*(rp_stream_conf_ctx_t **) conf) {
        return "is duplicate";
    }

    /* the main stream context */

    ctx = rp_pcalloc(cf->pool, sizeof(rp_stream_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    *(rp_stream_conf_ctx_t **) conf = ctx;

    /* count the number of the stream modules and set up their indices */

    rp_stream_max_module = rp_count_modules(cf->cycle, RP_STREAM_MODULE);


    /* the stream main_conf context, it's the same in the all stream contexts */

    ctx->main_conf = rp_pcalloc(cf->pool,
                                 sizeof(void *) * rp_stream_max_module);
    if (ctx->main_conf == NULL) {
        return RP_CONF_ERROR;
    }


    /*
     * the stream null srv_conf context, it is used to merge
     * the server{}s' srv_conf's
     */

    ctx->srv_conf = rp_pcalloc(cf->pool,
                                sizeof(void *) * rp_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return RP_CONF_ERROR;
    }


    /*
     * create the main_conf's and the null srv_conf's of the all stream modules
     */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            ctx->main_conf[mi] = module->create_main_conf(cf);
            if (ctx->main_conf[mi] == NULL) {
                return RP_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (ctx->srv_conf[mi] == NULL) {
                return RP_CONF_ERROR;
            }
        }
    }


    pcf = *cf;
    cf->ctx = ctx;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration) {
            if (module->preconfiguration(cf) != RP_OK) {
                return RP_CONF_ERROR;
            }
        }
    }


    /* parse inside the stream{} block */

    cf->module_type = RP_STREAM_MODULE;
    cf->cmd_type = RP_STREAM_MAIN_CONF;
    rv = rp_conf_parse(cf, NULL);

    if (rv != RP_CONF_OK) {
        *cf = pcf;
        return rv;
    }


    /* init stream{} main_conf's, merge the server{}s' srv_conf's */

    cmcf = ctx->main_conf[rp_stream_core_module.ctx_index];
    cscfp = cmcf->servers.elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        /* init stream{} main_conf's */

        cf->ctx = ctx;

        if (module->init_main_conf) {
            rv = module->init_main_conf(cf, ctx->main_conf[mi]);
            if (rv != RP_CONF_OK) {
                *cf = pcf;
                return rv;
            }
        }

        for (s = 0; s < cmcf->servers.nelts; s++) {

            /* merge the server{}s' srv_conf's */

            cf->ctx = cscfp[s]->ctx;

            if (module->merge_srv_conf) {
                rv = module->merge_srv_conf(cf,
                                            ctx->srv_conf[mi],
                                            cscfp[s]->ctx->srv_conf[mi]);
                if (rv != RP_CONF_OK) {
                    *cf = pcf;
                    return rv;
                }
            }
        }
    }

    if (rp_stream_init_phases(cf, cmcf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_STREAM_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->postconfiguration) {
            if (module->postconfiguration(cf) != RP_OK) {
                return RP_CONF_ERROR;
            }
        }
    }

    if (rp_stream_variables_init_vars(cf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    *cf = pcf;

    if (rp_stream_init_phase_handlers(cf, cmcf) != RP_OK) {
        return RP_CONF_ERROR;
    }

    if (rp_array_init(&ports, cf->temp_pool, 4, sizeof(rp_stream_conf_port_t))
        != RP_OK)
    {
        return RP_CONF_ERROR;
    }

    listen = cmcf->listen.elts;

    for (i = 0; i < cmcf->listen.nelts; i++) {
        if (rp_stream_add_ports(cf, &ports, &listen[i]) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    return rp_stream_optimize_servers(cf, &ports);
}


static rp_int_t
rp_stream_init_phases(rp_conf_t *cf, rp_stream_core_main_conf_t *cmcf)
{
    if (rp_array_init(&cmcf->phases[RP_STREAM_POST_ACCEPT_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_stream_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_STREAM_PREACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_stream_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_STREAM_ACCESS_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_stream_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_STREAM_SSL_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_stream_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_STREAM_PREREAD_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_stream_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->phases[RP_STREAM_LOG_PHASE].handlers,
                       cf->pool, 1, sizeof(rp_stream_handler_pt))
        != RP_OK)
    {
        return RP_ERROR;
    }

    return RP_OK;
}


static rp_int_t
rp_stream_init_phase_handlers(rp_conf_t *cf,
    rp_stream_core_main_conf_t *cmcf)
{
    rp_int_t                     j;
    rp_uint_t                    i, n;
    rp_stream_handler_pt        *h;
    rp_stream_phase_handler_t   *ph;
    rp_stream_phase_handler_pt   checker;

    n = 1 /* content phase */;

    for (i = 0; i < RP_STREAM_LOG_PHASE; i++) {
        n += cmcf->phases[i].handlers.nelts;
    }

    ph = rp_pcalloc(cf->pool,
                     n * sizeof(rp_stream_phase_handler_t) + sizeof(void *));
    if (ph == NULL) {
        return RP_ERROR;
    }

    cmcf->phase_engine.handlers = ph;
    n = 0;

    for (i = 0; i < RP_STREAM_LOG_PHASE; i++) {
        h = cmcf->phases[i].handlers.elts;

        switch (i) {

        case RP_STREAM_PREREAD_PHASE:
            checker = rp_stream_core_preread_phase;
            break;

        case RP_STREAM_CONTENT_PHASE:
            ph->checker = rp_stream_core_content_phase;
            n++;
            ph++;

            continue;

        default:
            checker = rp_stream_core_generic_phase;
        }

        n += cmcf->phases[i].handlers.nelts;

        for (j = cmcf->phases[i].handlers.nelts - 1; j >= 0; j--) {
            ph->checker = checker;
            ph->handler = h[j];
            ph->next = n;
            ph++;
        }
    }

    return RP_OK;
}


static rp_int_t
rp_stream_add_ports(rp_conf_t *cf, rp_array_t *ports,
    rp_stream_listen_t *listen)
{
    in_port_t                p;
    rp_uint_t               i;
    struct sockaddr         *sa;
    rp_stream_conf_port_t  *port;
    rp_stream_conf_addr_t  *addr;

    sa = listen->sockaddr;
    p = rp_inet_get_port(sa);

    port = ports->elts;
    for (i = 0; i < ports->nelts; i++) {

        if (p == port[i].port
            && listen->type == port[i].type
            && sa->sa_family == port[i].family)
        {
            /* a port is already in the port list */

            port = &port[i];
            goto found;
        }
    }

    /* add a port to the port list */

    port = rp_array_push(ports);
    if (port == NULL) {
        return RP_ERROR;
    }

    port->family = sa->sa_family;
    port->type = listen->type;
    port->port = p;

    if (rp_array_init(&port->addrs, cf->temp_pool, 2,
                       sizeof(rp_stream_conf_addr_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

found:

    addr = rp_array_push(&port->addrs);
    if (addr == NULL) {
        return RP_ERROR;
    }

    addr->opt = *listen;

    return RP_OK;
}


static char *
rp_stream_optimize_servers(rp_conf_t *cf, rp_array_t *ports)
{
    rp_uint_t                   i, p, last, bind_wildcard;
    rp_listening_t             *ls;
    rp_stream_port_t           *stport;
    rp_stream_conf_port_t      *port;
    rp_stream_conf_addr_t      *addr;
    rp_stream_core_srv_conf_t  *cscf;

    port = ports->elts;
    for (p = 0; p < ports->nelts; p++) {

        rp_sort(port[p].addrs.elts, (size_t) port[p].addrs.nelts,
                 sizeof(rp_stream_conf_addr_t), rp_stream_cmp_conf_addrs);

        addr = port[p].addrs.elts;
        last = port[p].addrs.nelts;

        /*
         * if there is the binding to the "*:port" then we need to bind()
         * to the "*:port" only and ignore the other bindings
         */

        if (addr[last - 1].opt.wildcard) {
            addr[last - 1].opt.bind = 1;
            bind_wildcard = 1;

        } else {
            bind_wildcard = 0;
        }

        i = 0;

        while (i < last) {

            if (bind_wildcard && !addr[i].opt.bind) {
                i++;
                continue;
            }

            ls = rp_create_listening(cf, addr[i].opt.sockaddr,
                                      addr[i].opt.socklen);
            if (ls == NULL) {
                return RP_CONF_ERROR;
            }

            ls->addr_ntop = 1;
            ls->handler = rp_stream_init_connection;
            ls->pool_size = 256;
            ls->type = addr[i].opt.type;

            cscf = addr->opt.ctx->srv_conf[rp_stream_core_module.ctx_index];

            ls->logp = cscf->error_log;
            ls->log.data = &ls->addr_text;
            ls->log.handler = rp_accept_log_error;

            ls->backlog = addr[i].opt.backlog;
            ls->rcvbuf = addr[i].opt.rcvbuf;
            ls->sndbuf = addr[i].opt.sndbuf;

            ls->wildcard = addr[i].opt.wildcard;

            ls->keepalive = addr[i].opt.so_keepalive;
#if (RP_HAVE_KEEPALIVE_TUNABLE)
            ls->keepidle = addr[i].opt.tcp_keepidle;
            ls->keepintvl = addr[i].opt.tcp_keepintvl;
            ls->keepcnt = addr[i].opt.tcp_keepcnt;
#endif

#if (RP_HAVE_INET6)
            ls->ipv6only = addr[i].opt.ipv6only;
#endif

#if (RP_HAVE_REUSEPORT)
            ls->reuseport = addr[i].opt.reuseport;
#endif

            stport = rp_palloc(cf->pool, sizeof(rp_stream_port_t));
            if (stport == NULL) {
                return RP_CONF_ERROR;
            }

            ls->servers = stport;

            stport->naddrs = i + 1;

            switch (ls->sockaddr->sa_family) {
#if (RP_HAVE_INET6)
            case AF_INET6:
                if (rp_stream_add_addrs6(cf, stport, addr) != RP_OK) {
                    return RP_CONF_ERROR;
                }
                break;
#endif
            default: /* AF_INET */
                if (rp_stream_add_addrs(cf, stport, addr) != RP_OK) {
                    return RP_CONF_ERROR;
                }
                break;
            }

            addr++;
            last--;
        }
    }

    return RP_CONF_OK;
}


static rp_int_t
rp_stream_add_addrs(rp_conf_t *cf, rp_stream_port_t *stport,
    rp_stream_conf_addr_t *addr)
{
    rp_uint_t             i;
    struct sockaddr_in    *sin;
    rp_stream_in_addr_t  *addrs;

    stport->addrs = rp_pcalloc(cf->pool,
                                stport->naddrs * sizeof(rp_stream_in_addr_t));
    if (stport->addrs == NULL) {
        return RP_ERROR;
    }

    addrs = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin = (struct sockaddr_in *) addr[i].opt.sockaddr;
        addrs[i].addr = sin->sin_addr.s_addr;

        addrs[i].conf.ctx = addr[i].opt.ctx;
#if (RP_STREAM_SSL)
        addrs[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
        addrs[i].conf.addr_text = addr[i].opt.addr_text;
    }

    return RP_OK;
}


#if (RP_HAVE_INET6)

static rp_int_t
rp_stream_add_addrs6(rp_conf_t *cf, rp_stream_port_t *stport,
    rp_stream_conf_addr_t *addr)
{
    rp_uint_t              i;
    struct sockaddr_in6    *sin6;
    rp_stream_in6_addr_t  *addrs6;

    stport->addrs = rp_pcalloc(cf->pool,
                                stport->naddrs * sizeof(rp_stream_in6_addr_t));
    if (stport->addrs == NULL) {
        return RP_ERROR;
    }

    addrs6 = stport->addrs;

    for (i = 0; i < stport->naddrs; i++) {

        sin6 = (struct sockaddr_in6 *) addr[i].opt.sockaddr;
        addrs6[i].addr6 = sin6->sin6_addr;

        addrs6[i].conf.ctx = addr[i].opt.ctx;
#if (RP_STREAM_SSL)
        addrs6[i].conf.ssl = addr[i].opt.ssl;
#endif
        addrs6[i].conf.proxy_protocol = addr[i].opt.proxy_protocol;
        addrs6[i].conf.addr_text = addr[i].opt.addr_text;
    }

    return RP_OK;
}

#endif


static rp_int_t
rp_stream_cmp_conf_addrs(const void *one, const void *two)
{
    rp_stream_conf_addr_t  *first, *second;

    first = (rp_stream_conf_addr_t *) one;
    second = (rp_stream_conf_addr_t *) two;

    if (first->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return 1;
    }

    if (second->opt.wildcard) {
        /* a wildcard must be the last resort, shift it to the end */
        return -1;
    }

    if (first->opt.bind && !second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return -1;
    }

    if (!first->opt.bind && second->opt.bind) {
        /* shift explicit bind()ed addresses to the start */
        return 1;
    }

    /* do not sort by default */

    return 0;
}
