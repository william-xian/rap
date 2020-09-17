
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_event.h>
#include <rp_mail.h>


static void *rp_mail_core_create_main_conf(rp_conf_t *cf);
static void *rp_mail_core_create_srv_conf(rp_conf_t *cf);
static char *rp_mail_core_merge_srv_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_mail_core_server(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_mail_core_listen(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_mail_core_protocol(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_mail_core_error_log(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_mail_core_resolver(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_mail_core_commands[] = {

    { rp_string("server"),
      RP_MAIL_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_NOARGS,
      rp_mail_core_server,
      0,
      0,
      NULL },

    { rp_string("listen"),
      RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_mail_core_listen,
      RP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("protocol"),
      RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_mail_core_protocol,
      RP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("timeout"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_core_srv_conf_t, timeout),
      NULL },

    { rp_string("server_name"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_str_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_core_srv_conf_t, server_name),
      NULL },

    { rp_string("error_log"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_mail_core_error_log,
      RP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("resolver"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_1MORE,
      rp_mail_core_resolver,
      RP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("resolver_timeout"),
      RP_MAIL_MAIN_CONF|RP_MAIL_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_MAIL_SRV_CONF_OFFSET,
      offsetof(rp_mail_core_srv_conf_t, resolver_timeout),
      NULL },

      rp_null_command
};


static rp_mail_module_t  rp_mail_core_module_ctx = {
    NULL,                                  /* protocol */

    rp_mail_core_create_main_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    rp_mail_core_create_srv_conf,         /* create server configuration */
    rp_mail_core_merge_srv_conf           /* merge server configuration */
};


rp_module_t  rp_mail_core_module = {
    RP_MODULE_V1,
    &rp_mail_core_module_ctx,             /* module context */
    rp_mail_core_commands,                /* module directives */
    RP_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static void *
rp_mail_core_create_main_conf(rp_conf_t *cf)
{
    rp_mail_core_main_conf_t  *cmcf;

    cmcf = rp_pcalloc(cf->pool, sizeof(rp_mail_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (rp_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(rp_mail_core_srv_conf_t *))
        != RP_OK)
    {
        return NULL;
    }

    if (rp_array_init(&cmcf->listen, cf->pool, 4, sizeof(rp_mail_listen_t))
        != RP_OK)
    {
        return NULL;
    }

    return cmcf;
}


static void *
rp_mail_core_create_srv_conf(rp_conf_t *cf)
{
    rp_mail_core_srv_conf_t  *cscf;

    cscf = rp_pcalloc(cf->pool, sizeof(rp_mail_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     cscf->protocol = NULL;
     *     cscf->error_log = NULL;
     */

    cscf->timeout = RP_CONF_UNSET_MSEC;
    cscf->resolver_timeout = RP_CONF_UNSET_MSEC;

    cscf->resolver = RP_CONF_UNSET_PTR;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    return cscf;
}


static char *
rp_mail_core_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_mail_core_srv_conf_t *prev = parent;
    rp_mail_core_srv_conf_t *conf = child;

    rp_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    rp_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout,
                              30000);


    rp_conf_merge_str_value(conf->server_name, prev->server_name, "");

    if (conf->server_name.len == 0) {
        conf->server_name = cf->cycle->hostname;
    }

    if (conf->protocol == NULL) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "unknown mail protocol for server in %s:%ui",
                      conf->file_name, conf->line);
        return RP_CONF_ERROR;
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    rp_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);

    return RP_CONF_OK;
}


static char *
rp_mail_core_server(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    rp_uint_t                  m;
    rp_conf_t                  pcf;
    rp_mail_module_t          *module;
    rp_mail_conf_ctx_t        *ctx, *mail_ctx;
    rp_mail_core_srv_conf_t   *cscf, **cscfp;
    rp_mail_core_main_conf_t  *cmcf;

    ctx = rp_pcalloc(cf->pool, sizeof(rp_mail_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    mail_ctx = cf->ctx;
    ctx->main_conf = mail_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = rp_pcalloc(cf->pool, sizeof(void *) * rp_mail_max_module);
    if (ctx->srv_conf == NULL) {
        return RP_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_MAIL_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return RP_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[rp_mail_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[rp_mail_core_module.ctx_index];

    cscfp = rp_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return RP_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RP_MAIL_SRV_CONF;

    rv = rp_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == RP_CONF_OK && !cscf->listen) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no \"listen\" is defined for server in %s:%ui",
                      cscf->file_name, cscf->line);
        return RP_CONF_ERROR;
    }

    return rv;
}


static char *
rp_mail_core_listen(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_core_srv_conf_t  *cscf = conf;

    rp_str_t                  *value, size;
    rp_url_t                   u;
    rp_uint_t                  i, n, m;
    rp_mail_listen_t          *ls, *als;
    rp_mail_module_t          *module;
    rp_mail_core_main_conf_t  *cmcf;

    cscf->listen = 1;

    value = cf->args->elts;

    rp_memzero(&u, sizeof(rp_url_t));

    u.url = value[1];
    u.listen = 1;

    if (rp_parse_url(cf->pool, &u) != RP_OK) {
        if (u.err) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return RP_CONF_ERROR;
    }

    cmcf = rp_mail_conf_get_module_main_conf(cf, rp_mail_core_module);

    ls = rp_array_push_n(&cmcf->listen, u.naddrs);
    if (ls == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(ls, sizeof(rp_mail_listen_t));

    ls->backlog = RP_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;
    ls->ctx = cf->ctx;

#if (RP_HAVE_INET6)
    ls->ipv6only = 1;
#endif

    if (cscf->protocol == NULL) {
        for (m = 0; cf->cycle->modules[m]; m++) {
            if (cf->cycle->modules[m]->type != RP_MAIL_MODULE) {
                continue;
            }

            module = cf->cycle->modules[m]->ctx;

            if (module->protocol == NULL) {
                continue;
            }

            for (i = 0; module->protocol->port[i]; i++) {
                if (module->protocol->port[i] == u.port) {
                    cscf->protocol = module->protocol;
                    break;
                }
            }
        }
    }

    for (i = 2; i < cf->args->nelts; i++) {

        if (rp_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (rp_strncmp(value[i].data, "backlog=", 8) == 0) {
            ls->backlog = rp_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if (ls->backlog == RP_ERROR || ls->backlog == 0) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->rcvbuf = rp_parse_size(&size);
            ls->bind = 1;

            if (ls->rcvbuf == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "sndbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->sndbuf = rp_parse_size(&size);
            ls->bind = 1;

            if (ls->sndbuf == RP_ERROR) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[i]);
                return RP_CONF_ERROR;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (RP_HAVE_INET6 && defined IPV6_V6ONLY)
            if (rp_strcmp(&value[i].data[10], "n") == 0) {
                ls->ipv6only = 1;

            } else if (rp_strcmp(&value[i].data[10], "ff") == 0) {
                ls->ipv6only = 0;

            } else {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "invalid ipv6only flags \"%s\"",
                                   &value[i].data[9]);
                return RP_CONF_ERROR;
            }

            ls->bind = 1;
            continue;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return RP_CONF_ERROR;
#endif
        }

        if (rp_strcmp(value[i].data, "ssl") == 0) {
#if (RP_MAIL_SSL)
            rp_mail_ssl_conf_t  *sslcf;

            sslcf = rp_mail_conf_get_module_srv_conf(cf, rp_mail_ssl_module);

            sslcf->listen = 1;
            sslcf->file = cf->conf_file->file.name.data;
            sslcf->line = cf->conf_file->line;

            ls->ssl = 1;

            continue;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "rp_mail_ssl_module");
            return RP_CONF_ERROR;
#endif
        }

        if (rp_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (rp_strcmp(&value[i].data[13], "on") == 0) {
                ls->so_keepalive = 1;

            } else if (rp_strcmp(&value[i].data[13], "off") == 0) {
                ls->so_keepalive = 2;

            } else {

#if (RP_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                rp_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = rp_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepidle = rp_parse_time(&s, 1);
                    if (ls->tcp_keepidle == (time_t) RP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = rp_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepintvl = rp_parse_time(&s, 1);
                    if (ls->tcp_keepintvl == (time_t) RP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    ls->tcp_keepcnt = rp_atoi(s.data, s.len);
                    if (ls->tcp_keepcnt == RP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                if (ls->tcp_keepidle == 0 && ls->tcp_keepintvl == 0
                    && ls->tcp_keepcnt == 0)
                {
                    goto invalid_so_keepalive;
                }

                ls->so_keepalive = 1;

#else

                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return RP_CONF_ERROR;

#endif
            }

            ls->bind = 1;

            continue;

#if (RP_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return RP_CONF_ERROR;
#endif
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return RP_CONF_ERROR;
    }

    als = cmcf->listen.elts;

    for (n = 0; n < u.naddrs; n++) {
        ls[n] = ls[0];

        ls[n].sockaddr = u.addrs[n].sockaddr;
        ls[n].socklen = u.addrs[n].socklen;
        ls[n].addr_text = u.addrs[n].name;
        ls[n].wildcard = rp_inet_wildcard(ls[n].sockaddr);

        for (i = 0; i < cmcf->listen.nelts - u.naddrs + n; i++) {

            if (rp_cmp_sockaddr(als[i].sockaddr, als[i].socklen,
                                 ls[n].sockaddr, ls[n].socklen, 1)
                != RP_OK)
            {
                continue;
            }

            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "duplicate \"%V\" address and port pair",
                               &ls[n].addr_text);
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}


static char *
rp_mail_core_protocol(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_core_srv_conf_t  *cscf = conf;

    rp_str_t          *value;
    rp_uint_t          m;
    rp_mail_module_t  *module;

    value = cf->args->elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_MAIL_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->protocol
            && rp_strcmp(module->protocol->name.data, value[1].data) == 0)
        {
            cscf->protocol = module->protocol;

            return RP_CONF_OK;
        }
    }

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "unknown protocol \"%V\"", &value[1]);
    return RP_CONF_ERROR;
}


static char *
rp_mail_core_error_log(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_core_srv_conf_t  *cscf = conf;

    return rp_log_set_log(cf, &cscf->error_log);
}


static char *
rp_mail_core_resolver(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_mail_core_srv_conf_t  *cscf = conf;

    rp_str_t  *value;

    value = cf->args->elts;

    if (cscf->resolver != RP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (rp_strcmp(value[1].data, "off") == 0) {
        cscf->resolver = NULL;
        return RP_CONF_OK;
    }

    cscf->resolver = rp_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}


char *
rp_mail_capabilities(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char  *p = conf;

    rp_str_t    *c, *value;
    rp_uint_t    i;
    rp_array_t  *a;

    a = (rp_array_t *) (p + cmd->offset);

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        c = rp_array_push(a);
        if (c == NULL) {
            return RP_CONF_ERROR;
        }

        *c = value[i];
    }

    return RP_CONF_OK;
}
