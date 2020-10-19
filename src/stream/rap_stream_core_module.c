
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


static rap_int_t rap_stream_core_preconfiguration(rap_conf_t *cf);
static void *rap_stream_core_create_main_conf(rap_conf_t *cf);
static char *rap_stream_core_init_main_conf(rap_conf_t *cf, void *conf);
static void *rap_stream_core_create_srv_conf(rap_conf_t *cf);
static char *rap_stream_core_merge_srv_conf(rap_conf_t *cf, void *parent,
    void *child);
static char *rap_stream_core_error_log(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_stream_core_server(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_stream_core_listen(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static char *rap_stream_core_resolver(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_command_t  rap_stream_core_commands[] = {

    { rap_string("variables_hash_max_size"),
      RAP_STREAM_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_STREAM_MAIN_CONF_OFFSET,
      offsetof(rap_stream_core_main_conf_t, variables_hash_max_size),
      NULL },

    { rap_string("variables_hash_bucket_size"),
      RAP_STREAM_MAIN_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_STREAM_MAIN_CONF_OFFSET,
      offsetof(rap_stream_core_main_conf_t, variables_hash_bucket_size),
      NULL },

    { rap_string("server"),
      RAP_STREAM_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_NOARGS,
      rap_stream_core_server,
      0,
      0,
      NULL },

    { rap_string("listen"),
      RAP_STREAM_SRV_CONF|RAP_CONF_1MORE,
      rap_stream_core_listen,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("error_log"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_1MORE,
      rap_stream_core_error_log,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("resolver"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_1MORE,
      rap_stream_core_resolver,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rap_string("resolver_timeout"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_core_srv_conf_t, resolver_timeout),
      NULL },

    { rap_string("proxy_protocol_timeout"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_core_srv_conf_t, proxy_protocol_timeout),
      NULL },

    { rap_string("tcp_nodelay"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_core_srv_conf_t, tcp_nodelay),
      NULL },

    { rap_string("preread_buffer_size"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_core_srv_conf_t, preread_buffer_size),
      NULL },

    { rap_string("preread_timeout"),
      RAP_STREAM_MAIN_CONF|RAP_STREAM_SRV_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_STREAM_SRV_CONF_OFFSET,
      offsetof(rap_stream_core_srv_conf_t, preread_timeout),
      NULL },

      rap_null_command
};


static rap_stream_module_t  rap_stream_core_module_ctx = {
    rap_stream_core_preconfiguration,      /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_stream_core_create_main_conf,      /* create main configuration */
    rap_stream_core_init_main_conf,        /* init main configuration */

    rap_stream_core_create_srv_conf,       /* create server configuration */
    rap_stream_core_merge_srv_conf         /* merge server configuration */
};


rap_module_t  rap_stream_core_module = {
    RAP_MODULE_V1,
    &rap_stream_core_module_ctx,           /* module context */
    rap_stream_core_commands,              /* module directives */
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


void
rap_stream_core_run_phases(rap_stream_session_t *s)
{
    rap_int_t                     rc;
    rap_stream_phase_handler_t   *ph;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_get_module_main_conf(s, rap_stream_core_module);

    ph = cmcf->phase_engine.handlers;

    while (ph[s->phase_handler].checker) {

        rc = ph[s->phase_handler].checker(s, &ph[s->phase_handler]);

        if (rc == RAP_OK) {
            return;
        }
    }
}


rap_int_t
rap_stream_core_generic_phase(rap_stream_session_t *s,
    rap_stream_phase_handler_t *ph)
{
    rap_int_t  rc;

    /*
     * generic phase checker,
     * used by all phases, except for preread and content
     */

    rap_log_debug1(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "generic phase: %ui", s->phase_handler);

    rc = ph->handler(s);

    if (rc == RAP_OK) {
        s->phase_handler = ph->next;
        return RAP_AGAIN;
    }

    if (rc == RAP_DECLINED) {
        s->phase_handler++;
        return RAP_AGAIN;
    }

    if (rc == RAP_AGAIN || rc == RAP_DONE) {
        return RAP_OK;
    }

    if (rc == RAP_ERROR) {
        rc = RAP_STREAM_INTERNAL_SERVER_ERROR;
    }

    rap_stream_finalize_session(s, rc);

    return RAP_OK;
}


rap_int_t
rap_stream_core_preread_phase(rap_stream_session_t *s,
    rap_stream_phase_handler_t *ph)
{
    size_t                       size;
    ssize_t                      n;
    rap_int_t                    rc;
    rap_connection_t            *c;
    rap_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = "prereading client data";

    cscf = rap_stream_get_module_srv_conf(s, rap_stream_core_module);

    if (c->read->timedout) {
        rc = RAP_STREAM_OK;

    } else if (c->read->timer_set) {
        rc = RAP_AGAIN;

    } else {
        rc = ph->handler(s);
    }

    while (rc == RAP_AGAIN) {

        if (c->buffer == NULL) {
            c->buffer = rap_create_temp_buf(c->pool, cscf->preread_buffer_size);
            if (c->buffer == NULL) {
                rc = RAP_ERROR;
                break;
            }
        }

        size = c->buffer->end - c->buffer->last;

        if (size == 0) {
            rap_log_error(RAP_LOG_ERR, c->log, 0, "preread buffer full");
            rc = RAP_STREAM_BAD_REQUEST;
            break;
        }

        if (c->read->eof) {
            rc = RAP_STREAM_OK;
            break;
        }

        if (!c->read->ready) {
            break;
        }

        n = c->recv(c, c->buffer->last, size);

        if (n == RAP_ERROR || n == 0) {
            rc = RAP_STREAM_OK;
            break;
        }

        if (n == RAP_AGAIN) {
            break;
        }

        c->buffer->last += n;

        rc = ph->handler(s);
    }

    if (rc == RAP_AGAIN) {
        if (rap_handle_read_event(c->read, 0) != RAP_OK) {
            rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
            return RAP_OK;
        }

        if (!c->read->timer_set) {
            rap_add_timer(c->read, cscf->preread_timeout);
        }

        c->read->handler = rap_stream_session_handler;

        return RAP_OK;
    }

    if (c->read->timer_set) {
        rap_del_timer(c->read);
    }

    if (rc == RAP_OK) {
        s->phase_handler = ph->next;
        return RAP_AGAIN;
    }

    if (rc == RAP_DECLINED) {
        s->phase_handler++;
        return RAP_AGAIN;
    }

    if (rc == RAP_DONE) {
        return RAP_OK;
    }

    if (rc == RAP_ERROR) {
        rc = RAP_STREAM_INTERNAL_SERVER_ERROR;
    }

    rap_stream_finalize_session(s, rc);

    return RAP_OK;
}


rap_int_t
rap_stream_core_content_phase(rap_stream_session_t *s,
    rap_stream_phase_handler_t *ph)
{
    rap_connection_t            *c;
    rap_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = NULL;

    cscf = rap_stream_get_module_srv_conf(s, rap_stream_core_module);

    if (c->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && rap_tcp_nodelay(c) != RAP_OK)
    {
        rap_stream_finalize_session(s, RAP_STREAM_INTERNAL_SERVER_ERROR);
        return RAP_OK;
    }

    cscf->handler(s);

    return RAP_OK;
}


static rap_int_t
rap_stream_core_preconfiguration(rap_conf_t *cf)
{
    return rap_stream_variables_add_core_vars(cf);
}


static void *
rap_stream_core_create_main_conf(rap_conf_t *cf)
{
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_pcalloc(cf->pool, sizeof(rap_stream_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (rap_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(rap_stream_core_srv_conf_t *))
        != RAP_OK)
    {
        return NULL;
    }

    if (rap_array_init(&cmcf->listen, cf->pool, 4, sizeof(rap_stream_listen_t))
        != RAP_OK)
    {
        return NULL;
    }

    cmcf->variables_hash_max_size = RAP_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = RAP_CONF_UNSET_UINT;

    return cmcf;
}


static char *
rap_stream_core_init_main_conf(rap_conf_t *cf, void *conf)
{
    rap_stream_core_main_conf_t *cmcf = conf;

    rap_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    rap_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
               rap_align(cmcf->variables_hash_bucket_size, rap_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return RAP_CONF_OK;
}


static void *
rap_stream_core_create_srv_conf(rap_conf_t *cf)
{
    rap_stream_core_srv_conf_t  *cscf;

    cscf = rap_pcalloc(cf->pool, sizeof(rap_stream_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     cscf->handler = NULL;
     *     cscf->error_log = NULL;
     */

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;
    cscf->resolver_timeout = RAP_CONF_UNSET_MSEC;
    cscf->proxy_protocol_timeout = RAP_CONF_UNSET_MSEC;
    cscf->tcp_nodelay = RAP_CONF_UNSET;
    cscf->preread_buffer_size = RAP_CONF_UNSET_SIZE;
    cscf->preread_timeout = RAP_CONF_UNSET_MSEC;

    return cscf;
}


static char *
rap_stream_core_merge_srv_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_stream_core_srv_conf_t *prev = parent;
    rap_stream_core_srv_conf_t *conf = child;

    rap_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in stream {} context
             * to inherit it in all servers
             */

            prev->resolver = rap_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return RAP_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    if (conf->handler == NULL) {
        rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                      "no handler for server in %s:%ui",
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

    rap_conf_merge_msec_value(conf->proxy_protocol_timeout,
                              prev->proxy_protocol_timeout, 30000);

    rap_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    rap_conf_merge_size_value(conf->preread_buffer_size,
                              prev->preread_buffer_size, 16384);

    rap_conf_merge_msec_value(conf->preread_timeout,
                              prev->preread_timeout, 30000);

    return RAP_CONF_OK;
}


static char *
rap_stream_core_error_log(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_core_srv_conf_t  *cscf = conf;

    return rap_log_set_log(cf, &cscf->error_log);
}


static char *
rap_stream_core_server(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    char                         *rv;
    void                         *mconf;
    rap_uint_t                    m;
    rap_conf_t                    pcf;
    rap_stream_module_t          *module;
    rap_stream_conf_ctx_t        *ctx, *stream_ctx;
    rap_stream_core_srv_conf_t   *cscf, **cscfp;
    rap_stream_core_main_conf_t  *cmcf;

    ctx = rap_pcalloc(cf->pool, sizeof(rap_stream_conf_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = rap_pcalloc(cf->pool,
                                sizeof(void *) * rap_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RAP_STREAM_MODULE) {
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

    cscf = ctx->srv_conf[rap_stream_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[rap_stream_core_module.ctx_index];

    cscfp = rap_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return RAP_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RAP_STREAM_SRV_CONF;

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
rap_stream_core_listen(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_core_srv_conf_t  *cscf = conf;

    rap_str_t                    *value, size;
    rap_url_t                     u;
    rap_uint_t                    i, n, backlog;
    rap_stream_listen_t          *ls, *als;
    rap_stream_core_main_conf_t  *cmcf;

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

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);

    ls = rap_array_push_n(&cmcf->listen, u.naddrs);
    if (ls == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(ls, sizeof(rap_stream_listen_t));

    ls->backlog = RAP_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;
    ls->type = SOCK_STREAM;
    ls->ctx = cf->ctx;

#if (RAP_HAVE_INET6)
    ls->ipv6only = 1;
#endif

    backlog = 0;

    for (i = 2; i < cf->args->nelts; i++) {

#if !(RAP_WIN32)
        if (rap_strcmp(value[i].data, "udp") == 0) {
            ls->type = SOCK_DGRAM;
            continue;
        }
#endif

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

            backlog = 1;

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

        if (rap_strcmp(value[i].data, "reuseport") == 0) {
#if (RAP_HAVE_REUSEPORT)
            ls->reuseport = 1;
            ls->bind = 1;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (rap_strcmp(value[i].data, "ssl") == 0) {
#if (RAP_STREAM_SSL)
            rap_stream_ssl_conf_t  *sslcf;

            sslcf = rap_stream_conf_get_module_srv_conf(cf,
                                                        rap_stream_ssl_module);

            sslcf->listen = 1;
            sslcf->file = cf->conf_file->file.name.data;
            sslcf->line = cf->conf_file->line;

            ls->ssl = 1;

            continue;
#else
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "rap_stream_ssl_module");
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

        if (rap_strcmp(value[i].data, "proxy_protocol") == 0) {
            ls->proxy_protocol = 1;
            continue;
        }

        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return RAP_CONF_ERROR;
    }

    if (ls->type == SOCK_DGRAM) {
        if (backlog) {
            return "\"backlog\" parameter is incompatible with \"udp\"";
        }

#if (RAP_STREAM_SSL)
        if (ls->ssl) {
            return "\"ssl\" parameter is incompatible with \"udp\"";
        }
#endif

        if (ls->so_keepalive) {
            return "\"so_keepalive\" parameter is incompatible with \"udp\"";
        }

        if (ls->proxy_protocol) {
            return "\"proxy_protocol\" parameter is incompatible with \"udp\"";
        }
    }

    als = cmcf->listen.elts;

    for (n = 0; n < u.naddrs; n++) {
        ls[n] = ls[0];

        ls[n].sockaddr = u.addrs[n].sockaddr;
        ls[n].socklen = u.addrs[n].socklen;
        ls[n].addr_text = u.addrs[n].name;
        ls[n].wildcard = rap_inet_wildcard(ls[n].sockaddr);

        for (i = 0; i < cmcf->listen.nelts - u.naddrs + n; i++) {
            if (ls[n].type != als[i].type) {
                continue;
            }

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
rap_stream_core_resolver(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_core_srv_conf_t  *cscf = conf;

    rap_str_t  *value;

    if (cscf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    cscf->resolver = rap_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
