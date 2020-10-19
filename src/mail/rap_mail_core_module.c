
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_mail.h>


static void *rap_mail_core_create_main_conf(rap_conf_t *cf);
static void *rap_mail_core_create_srv_conf(rap_conf_t *cf);
static char *rap_mail_core_merge_srv_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_mail_core_server(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_mail_core_listen(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_mail_core_protocol(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_mail_core_error_log(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_mail_core_resolver(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_mail_core_commands[] = {

    { rap_string("server"),
      RAP_MAIL_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_NOARGS,
      rap_mail_core_server,
      0,
      0,
      NULL },

    { rap_string("listen"),
      RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_mail_core_listen,
      RAP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("protocol"),
      RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_mail_core_protocol,
      RAP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("timeout"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_core_srv_conf_t, timeout),
      NULL },

    { rap_string("server_name"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_str_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_core_srv_conf_t, server_name),
      NULL },

    { rap_string("error_log"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_mail_core_error_log,
      RAP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("resolver"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_1MORE,
      rap_mail_core_resolver,
      RAP_MAIL_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("resolver_timeout"),
      RAP_MAIL_MAIN_CONF|RAP_MAIL_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_MAIL_SRV_CONF_OFFSET,
      offsetof(rap_mail_core_srv_conf_t, resolver_timeout),
      NULL },

      rap_null_command
};


static rap_mail_module_t  rap_mail_core_module_ctx = {
    NULL,                                  /* protocol */

    rap_mail_core_create_main_conf,        /* create main configuration */
    NULL,                                  /* init main configuration */

    rap_mail_core_create_srv_conf,         /* create server configuration */
    rap_mail_core_merge_srv_conf           /* merge server configuration */
};


rap_module_t  rap_mail_core_module = {
    RAP_MODULE_V1,
    &rap_mail_core_module_ctx,             /* module context */
    rap_mail_core_commands,                /* module directives */
    RAP_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static void *
rap_mail_core_create_main_conf(rap_conf_t *cf)
{
    rap_mail_core_main_conf_t  *cmcf;

    cmcf = rap_pcalloc(cf->pool, sizeof(rap_mail_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (rap_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(rap_mail_core_srv_conf_t *))
        != RAP_OK)
    {
        return NULL;
    }

    if (rap_array_init(&cmcf->listen, cf->pool, 4, sizeof(rap_mail_listen_t))
        != RAP_OK)
    {
        return NULL;
    }

    return cmcf;
}


static void *
rap_mail_core_create_srv_conf(rap_conf_t *cf)
{
    rap_mail_core_srv_conf_t  *cscf;

    cscf = rap_pcalloc(cf->pool, sizeof(rap_mail_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     cscf->protocol = NULL;
     *     cscf->error_log = NULL;
     */

    cscf->timeout = RAP_CONF_UNSET_MSEC;
    cscf->resolver_timeout = RAP_CONF_UNSET_MSEC;

    cscf->resolver = RAP_CONF_UNSET_PTR;

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;

    return cscf;
}


static char *
rap_mail_core_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_mail_core_srv_conf_t *prev = parent;
    rap_mail_core_srv_conf_t *conf = child;

    rap_conf_merge_msec_value(conf->timeout, prev->timeout, 60000);
    rap_conf_merge_msec_value(conf->resolver_timeout, prev->resolver_timeout,
                              30000);


    rap_conf_merge_str_value(conf->server_name, prev->server_name, "");

    if (conf->server_name.len == 0) {
        conf->server_name = cf->cycle->hostname;
    }

    if (conf->protocol == NULL) {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "unknown mail protocol for server in %s:%ui",
                      conf->file_name, conf->line);
        return RAP_CONF_ERROR;
    }

    if (conf->error_log == NULL) {
        if (prev->error_log) {
            conf->error_log = prev->error_log;
        } else {
            conf->error_log = &cf->cycle->new_log;
        }
    }

    rap_conf_merge_ptr_value(conf->resolver, prev->resolver, NULL);

    return RAP_CONF_OK;
}


static char *
rap_mail_core_server(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char                       *rv;
    void                       *mconf;
    rap_uint_t                  m;
    rap_conf_t                  pcf;
    rap_mail_module_t          *module;
    rap_mail_conf_ctx_t        *ctx, *mail_ctx;
    rap_mail_core_srv_conf_t   *cscf, **cscfp;
    rap_mail_core_main_conf_t  *cmcf;

    ctx = rap_pcalloc(cf->pool, sizeof(rap_mail_conf_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    mail_ctx = cf->ctx;
    ctx->main_conf = mail_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = rap_pcalloc(cf->pool, sizeof(void *) * rap_mail_max_module);
    if (ctx->srv_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RAP_MAIL_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return RAP_CONF_ERROR;
            }

            ctx->srv_conf[cf->cycle->modules[m]->ctx_index] = mconf;
        }
    }

    /* the server configuration context */

    cscf = ctx->srv_conf[rap_mail_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[rap_mail_core_module.ctx_index];

    cscfp = rap_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return RAP_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RAP_MAIL_SRV_CONF;

    rv = rap_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv == RAP_CONF_OK && !cscf->listen) {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no \"listen\" is defined for server in %s:%ui",
                      cscf->file_name, cscf->line);
        return RAP_CONF_ERROR;
    }

    return rv;
}


static char *
rap_mail_core_listen(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_core_srv_conf_t  *cscf = conf;

    rap_str_t                  *value, size;
    rap_url_t                   u;
    rap_uint_t                  i, n, m;
    rap_mail_listen_t          *ls, *als;
    rap_mail_module_t          *module;
    rap_mail_core_main_conf_t  *cmcf;

    cscf->listen = 1;

    value = cf->args->elts;

    rap_memzero(&u, sizeof(rap_url_t));

    u.url = value[1];
    u.listen = 1;

    if (rap_parse_url(cf->pool, &u) != RAP_OK) {
        if (u.err) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "%s in \"%V\" of the \"listen\" directive",
                               u.err, &u.url);
        }

        return RAP_CONF_ERROR;
    }

    cmcf = rap_mail_conf_get_module_main_conf(cf, rap_mail_core_module);

    ls = rap_array_push_n(&cmcf->listen, u.naddrs);
    if (ls == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(ls, sizeof(rap_mail_listen_t));

    ls->backlog = RAP_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;
    ls->ctx = cf->ctx;

#if (RAP_HAVE_INET6)
    ls->ipv6only = 1;
#endif

    if (cscf->protocol == NULL) {
        for (m = 0; cf->cycle->modules[m]; m++) {
            if (cf->cycle->modules[m]->type != RAP_MAIL_MODULE) {
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

        if (rap_strcmp(value[i].data, "bind") == 0) {
            ls->bind = 1;
            continue;
        }

        if (rap_strncmp(value[i].data, "backlog=", 8) == 0) {
            ls->backlog = rap_atoi(value[i].data + 8, value[i].len - 8);
            ls->bind = 1;

            if (ls->backlog == RAP_ERROR || ls->backlog == 0) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid backlog \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "rcvbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->rcvbuf = rap_parse_size(&size);
            ls->bind = 1;

            if (ls->rcvbuf == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid rcvbuf \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "sndbuf=", 7) == 0) {
            size.len = value[i].len - 7;
            size.data = value[i].data + 7;

            ls->sndbuf = rap_parse_size(&size);
            ls->bind = 1;

            if (ls->sndbuf == RAP_ERROR) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid sndbuf \"%V\"", &value[i]);
                return RAP_CONF_ERROR;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "ipv6only=o", 10) == 0) {
#if (RAP_HAVE_INET6 && defined IPV6_V6ONLY)
            if (rap_strcmp(&value[i].data[10], "n") == 0) {
                ls->ipv6only = 1;

            } else if (rap_strcmp(&value[i].data[10], "ff") == 0) {
                ls->ipv6only = 0;

            } else {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "invalid ipv6only flags \"%s\"",
                                   &value[i].data[9]);
                return RAP_CONF_ERROR;
            }

            ls->bind = 1;
            continue;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "bind ipv6only is not supported "
                               "on this platform");
            return RAP_CONF_ERROR;
#endif
        }

        if (rap_strcmp(value[i].data, "ssl") == 0) {
#if (RAP_MAIL_SSL)
            rap_mail_ssl_conf_t  *sslcf;

            sslcf = rap_mail_conf_get_module_srv_conf(cf, rap_mail_ssl_module);

            sslcf->listen = 1;
            sslcf->file = cf->conf_file->file.name.data;
            sslcf->line = cf->conf_file->line;

            ls->ssl = 1;

            continue;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "rap_mail_ssl_module");
            return RAP_CONF_ERROR;
#endif
        }

        if (rap_strncmp(value[i].data, "so_keepalive=", 13) == 0) {

            if (rap_strcmp(&value[i].data[13], "on") == 0) {
                ls->so_keepalive = 1;

            } else if (rap_strcmp(&value[i].data[13], "off") == 0) {
                ls->so_keepalive = 2;

            } else {

#if (RAP_HAVE_KEEPALIVE_TUNABLE)
                u_char     *p, *end;
                rap_str_t   s;

                end = value[i].data + value[i].len;
                s.data = value[i].data + 13;

                p = rap_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepidle = rap_parse_time(&s, 1);
                    if (ls->tcp_keepidle == (time_t) RAP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                p = rap_strlchr(s.data, end, ':');
                if (p == NULL) {
                    p = end;
                }

                if (p > s.data) {
                    s.len = p - s.data;

                    ls->tcp_keepintvl = rap_parse_time(&s, 1);
                    if (ls->tcp_keepintvl == (time_t) RAP_ERROR) {
                        goto invalid_so_keepalive;
                    }
                }

                s.data = (p < end) ? (p + 1) : end;

                if (s.data < end) {
                    s.len = end - s.data;

                    ls->tcp_keepcnt = rap_atoi(s.data, s.len);
                    if (ls->tcp_keepcnt == RAP_ERROR) {
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

                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "the \"so_keepalive\" parameter accepts "
                                   "only \"on\" or \"off\" on this platform");
                return RAP_CONF_ERROR;

#endif
            }

            ls->bind = 1;

            continue;

#if (RAP_HAVE_KEEPALIVE_TUNABLE)
        invalid_so_keepalive:

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "invalid so_keepalive value: \"%s\"",
                               &value[i].data[13]);
            return RAP_CONF_ERROR;
#endif
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return RAP_CONF_ERROR;
    }

    als = cmcf->listen.elts;

    for (n = 0; n < u.naddrs; n++) {
        ls[n] = ls[0];

        ls[n].sockaddr = u.addrs[n].sockaddr;
        ls[n].socklen = u.addrs[n].socklen;
        ls[n].addr_text = u.addrs[n].name;
        ls[n].wildcard = rap_inet_wildcard(ls[n].sockaddr);

        for (i = 0; i < cmcf->listen.nelts - u.naddrs + n; i++) {

            if (rap_cmp_sockaddr(als[i].sockaddr, als[i].socklen,
                                 ls[n].sockaddr, ls[n].socklen, 1)
                != RAP_OK)
            {
                continue;
            }

            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "duplicate \"%V\" address and port pair",
                               &ls[n].addr_text);
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}


static char *
rap_mail_core_protocol(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_core_srv_conf_t  *cscf = conf;

    rap_str_t          *value;
    rap_uint_t          m;
    rap_mail_module_t  *module;

    value = cf->args->elts;

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RAP_MAIL_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->protocol
            && rap_strcmp(module->protocol->name.data, value[1].data) == 0)
        {
            cscf->protocol = module->protocol;

            return RAP_CONF_OK;
        }
    }

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "unknown protocol \"%V\"", &value[1]);
    return RAP_CONF_ERROR;
}


static char *
rap_mail_core_error_log(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_core_srv_conf_t  *cscf = conf;

    return rap_log_set_log(cf, &cscf->error_log);
}


static char *
rap_mail_core_resolver(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_mail_core_srv_conf_t  *cscf = conf;

    rap_str_t  *value;

    value = cf->args->elts;

    if (cscf->resolver != RAP_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    if (rap_strcmp(value[1].data, "off") == 0) {
        cscf->resolver = NULL;
        return RAP_CONF_OK;
    }

    cscf->resolver = rap_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}


char *
rap_mail_capabilities(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char  *p = conf;

    rap_str_t    *c, *value;
    rap_uint_t    i;
    rap_array_t  *a;

    a = (rap_array_t *) (p + cmd->offset);

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        c = rap_array_push(a);
        if (c == NULL) {
            return RAP_CONF_ERROR;
        }

        *c = value[i];
    }

    return RAP_CONF_OK;
}
