
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


static rp_int_t rp_stream_core_preconfiguration(rp_conf_t *cf);
static void *rp_stream_core_create_main_conf(rp_conf_t *cf);
static char *rp_stream_core_init_main_conf(rp_conf_t *cf, void *conf);
static void *rp_stream_core_create_srv_conf(rp_conf_t *cf);
static char *rp_stream_core_merge_srv_conf(rp_conf_t *cf, void *parent,
    void *child);
static char *rp_stream_core_error_log(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_core_server(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_core_listen(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static char *rp_stream_core_resolver(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_command_t  rp_stream_core_commands[] = {

    { rp_string("variables_hash_max_size"),
      RP_STREAM_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_STREAM_MAIN_CONF_OFFSET,
      offsetof(rp_stream_core_main_conf_t, variables_hash_max_size),
      NULL },

    { rp_string("variables_hash_bucket_size"),
      RP_STREAM_MAIN_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_STREAM_MAIN_CONF_OFFSET,
      offsetof(rp_stream_core_main_conf_t, variables_hash_bucket_size),
      NULL },

    { rp_string("server"),
      RP_STREAM_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_NOARGS,
      rp_stream_core_server,
      0,
      0,
      NULL },

    { rp_string("listen"),
      RP_STREAM_SRV_CONF|RP_CONF_1MORE,
      rp_stream_core_listen,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("error_log"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_1MORE,
      rp_stream_core_error_log,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("resolver"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_1MORE,
      rp_stream_core_resolver,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { rp_string("resolver_timeout"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_core_srv_conf_t, resolver_timeout),
      NULL },

    { rp_string("proxy_protocol_timeout"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_core_srv_conf_t, proxy_protocol_timeout),
      NULL },

    { rp_string("tcp_nodelay"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_core_srv_conf_t, tcp_nodelay),
      NULL },

    { rp_string("preread_buffer_size"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_core_srv_conf_t, preread_buffer_size),
      NULL },

    { rp_string("preread_timeout"),
      RP_STREAM_MAIN_CONF|RP_STREAM_SRV_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_STREAM_SRV_CONF_OFFSET,
      offsetof(rp_stream_core_srv_conf_t, preread_timeout),
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_core_module_ctx = {
    rp_stream_core_preconfiguration,      /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rp_stream_core_create_main_conf,      /* create main configuration */
    rp_stream_core_init_main_conf,        /* init main configuration */

    rp_stream_core_create_srv_conf,       /* create server configuration */
    rp_stream_core_merge_srv_conf         /* merge server configuration */
};


rp_module_t  rp_stream_core_module = {
    RP_MODULE_V1,
    &rp_stream_core_module_ctx,           /* module context */
    rp_stream_core_commands,              /* module directives */
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


void
rp_stream_core_run_phases(rp_stream_session_t *s)
{
    rp_int_t                     rc;
    rp_stream_phase_handler_t   *ph;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_get_module_main_conf(s, rp_stream_core_module);

    ph = cmcf->phase_engine.handlers;

    while (ph[s->phase_handler].checker) {

        rc = ph[s->phase_handler].checker(s, &ph[s->phase_handler]);

        if (rc == RP_OK) {
            return;
        }
    }
}


rp_int_t
rp_stream_core_generic_phase(rp_stream_session_t *s,
    rp_stream_phase_handler_t *ph)
{
    rp_int_t  rc;

    /*
     * generic phase checker,
     * used by all phases, except for preread and content
     */

    rp_log_debug1(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                   "generic phase: %ui", s->phase_handler);

    rc = ph->handler(s);

    if (rc == RP_OK) {
        s->phase_handler = ph->next;
        return RP_AGAIN;
    }

    if (rc == RP_DECLINED) {
        s->phase_handler++;
        return RP_AGAIN;
    }

    if (rc == RP_AGAIN || rc == RP_DONE) {
        return RP_OK;
    }

    if (rc == RP_ERROR) {
        rc = RP_STREAM_INTERNAL_SERVER_ERROR;
    }

    rp_stream_finalize_session(s, rc);

    return RP_OK;
}


rp_int_t
rp_stream_core_preread_phase(rp_stream_session_t *s,
    rp_stream_phase_handler_t *ph)
{
    size_t                       size;
    ssize_t                      n;
    rp_int_t                    rc;
    rp_connection_t            *c;
    rp_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = "prereading client data";

    cscf = rp_stream_get_module_srv_conf(s, rp_stream_core_module);

    if (c->read->timedout) {
        rc = RP_STREAM_OK;

    } else if (c->read->timer_set) {
        rc = RP_AGAIN;

    } else {
        rc = ph->handler(s);
    }

    while (rc == RP_AGAIN) {

        if (c->buffer == NULL) {
            c->buffer = rp_create_temp_buf(c->pool, cscf->preread_buffer_size);
            if (c->buffer == NULL) {
                rc = RP_ERROR;
                break;
            }
        }

        size = c->buffer->end - c->buffer->last;

        if (size == 0) {
            rp_log_error(RP_LOG_ERR, c->log, 0, "preread buffer full");
            rc = RP_STREAM_BAD_REQUEST;
            break;
        }

        if (c->read->eof) {
            rc = RP_STREAM_OK;
            break;
        }

        if (!c->read->ready) {
            break;
        }

        n = c->recv(c, c->buffer->last, size);

        if (n == RP_ERROR || n == 0) {
            rc = RP_STREAM_OK;
            break;
        }

        if (n == RP_AGAIN) {
            break;
        }

        c->buffer->last += n;

        rc = ph->handler(s);
    }

    if (rc == RP_AGAIN) {
        if (rp_handle_read_event(c->read, 0) != RP_OK) {
            rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
            return RP_OK;
        }

        if (!c->read->timer_set) {
            rp_add_timer(c->read, cscf->preread_timeout);
        }

        c->read->handler = rp_stream_session_handler;

        return RP_OK;
    }

    if (c->read->timer_set) {
        rp_del_timer(c->read);
    }

    if (rc == RP_OK) {
        s->phase_handler = ph->next;
        return RP_AGAIN;
    }

    if (rc == RP_DECLINED) {
        s->phase_handler++;
        return RP_AGAIN;
    }

    if (rc == RP_DONE) {
        return RP_OK;
    }

    if (rc == RP_ERROR) {
        rc = RP_STREAM_INTERNAL_SERVER_ERROR;
    }

    rp_stream_finalize_session(s, rc);

    return RP_OK;
}


rp_int_t
rp_stream_core_content_phase(rp_stream_session_t *s,
    rp_stream_phase_handler_t *ph)
{
    rp_connection_t            *c;
    rp_stream_core_srv_conf_t  *cscf;

    c = s->connection;

    c->log->action = NULL;

    cscf = rp_stream_get_module_srv_conf(s, rp_stream_core_module);

    if (c->type == SOCK_STREAM
        && cscf->tcp_nodelay
        && rp_tcp_nodelay(c) != RP_OK)
    {
        rp_stream_finalize_session(s, RP_STREAM_INTERNAL_SERVER_ERROR);
        return RP_OK;
    }

    cscf->handler(s);

    return RP_OK;
}


static rp_int_t
rp_stream_core_preconfiguration(rp_conf_t *cf)
{
    return rp_stream_variables_add_core_vars(cf);
}


static void *
rp_stream_core_create_main_conf(rp_conf_t *cf)
{
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_pcalloc(cf->pool, sizeof(rp_stream_core_main_conf_t));
    if (cmcf == NULL) {
        return NULL;
    }

    if (rp_array_init(&cmcf->servers, cf->pool, 4,
                       sizeof(rp_stream_core_srv_conf_t *))
        != RP_OK)
    {
        return NULL;
    }

    if (rp_array_init(&cmcf->listen, cf->pool, 4, sizeof(rp_stream_listen_t))
        != RP_OK)
    {
        return NULL;
    }

    cmcf->variables_hash_max_size = RP_CONF_UNSET_UINT;
    cmcf->variables_hash_bucket_size = RP_CONF_UNSET_UINT;

    return cmcf;
}


static char *
rp_stream_core_init_main_conf(rp_conf_t *cf, void *conf)
{
    rp_stream_core_main_conf_t *cmcf = conf;

    rp_conf_init_uint_value(cmcf->variables_hash_max_size, 1024);
    rp_conf_init_uint_value(cmcf->variables_hash_bucket_size, 64);

    cmcf->variables_hash_bucket_size =
               rp_align(cmcf->variables_hash_bucket_size, rp_cacheline_size);

    if (cmcf->ncaptures) {
        cmcf->ncaptures = (cmcf->ncaptures + 1) * 3;
    }

    return RP_CONF_OK;
}


static void *
rp_stream_core_create_srv_conf(rp_conf_t *cf)
{
    rp_stream_core_srv_conf_t  *cscf;

    cscf = rp_pcalloc(cf->pool, sizeof(rp_stream_core_srv_conf_t));
    if (cscf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     cscf->handler = NULL;
     *     cscf->error_log = NULL;
     */

    cscf->file_name = cf->conf_file->file.name.data;
    cscf->line = cf->conf_file->line;
    cscf->resolver_timeout = RP_CONF_UNSET_MSEC;
    cscf->proxy_protocol_timeout = RP_CONF_UNSET_MSEC;
    cscf->tcp_nodelay = RP_CONF_UNSET;
    cscf->preread_buffer_size = RP_CONF_UNSET_SIZE;
    cscf->preread_timeout = RP_CONF_UNSET_MSEC;

    return cscf;
}


static char *
rp_stream_core_merge_srv_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_stream_core_srv_conf_t *prev = parent;
    rp_stream_core_srv_conf_t *conf = child;

    rp_conf_merge_msec_value(conf->resolver_timeout,
                              prev->resolver_timeout, 30000);

    if (conf->resolver == NULL) {

        if (prev->resolver == NULL) {

            /*
             * create dummy resolver in stream {} context
             * to inherit it in all servers
             */

            prev->resolver = rp_resolver_create(cf, NULL, 0);
            if (prev->resolver == NULL) {
                return RP_CONF_ERROR;
            }
        }

        conf->resolver = prev->resolver;
    }

    if (conf->handler == NULL) {
        rp_log_error(RP_LOG_EMERG, cf->log, 0,
                      "no handler for server in %s:%ui",
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

    rp_conf_merge_msec_value(conf->proxy_protocol_timeout,
                              prev->proxy_protocol_timeout, 30000);

    rp_conf_merge_value(conf->tcp_nodelay, prev->tcp_nodelay, 1);

    rp_conf_merge_size_value(conf->preread_buffer_size,
                              prev->preread_buffer_size, 16384);

    rp_conf_merge_msec_value(conf->preread_timeout,
                              prev->preread_timeout, 30000);

    return RP_CONF_OK;
}


static char *
rp_stream_core_error_log(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_core_srv_conf_t  *cscf = conf;

    return rp_log_set_log(cf, &cscf->error_log);
}


static char *
rp_stream_core_server(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    char                         *rv;
    void                         *mconf;
    rp_uint_t                    m;
    rp_conf_t                    pcf;
    rp_stream_module_t          *module;
    rp_stream_conf_ctx_t        *ctx, *stream_ctx;
    rp_stream_core_srv_conf_t   *cscf, **cscfp;
    rp_stream_core_main_conf_t  *cmcf;

    ctx = rp_pcalloc(cf->pool, sizeof(rp_stream_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    /* the server{}'s srv_conf */

    ctx->srv_conf = rp_pcalloc(cf->pool,
                                sizeof(void *) * rp_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return RP_CONF_ERROR;
    }

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != RP_STREAM_MODULE) {
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

    cscf = ctx->srv_conf[rp_stream_core_module.ctx_index];
    cscf->ctx = ctx;

    cmcf = ctx->main_conf[rp_stream_core_module.ctx_index];

    cscfp = rp_array_push(&cmcf->servers);
    if (cscfp == NULL) {
        return RP_CONF_ERROR;
    }

    *cscfp = cscf;


    /* parse inside server{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RP_STREAM_SRV_CONF;

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
rp_stream_core_listen(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_core_srv_conf_t  *cscf = conf;

    rp_str_t                    *value, size;
    rp_url_t                     u;
    rp_uint_t                    i, n, backlog;
    rp_stream_listen_t          *ls, *als;
    rp_stream_core_main_conf_t  *cmcf;

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

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    ls = rp_array_push_n(&cmcf->listen, u.naddrs);
    if (ls == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(ls, sizeof(rp_stream_listen_t));

    ls->backlog = RP_LISTEN_BACKLOG;
    ls->rcvbuf = -1;
    ls->sndbuf = -1;
    ls->type = SOCK_STREAM;
    ls->ctx = cf->ctx;

#if (RP_HAVE_INET6)
    ls->ipv6only = 1;
#endif

    backlog = 0;

    for (i = 2; i < cf->args->nelts; i++) {

#if !(RP_WIN32)
        if (rp_strcmp(value[i].data, "udp") == 0) {
            ls->type = SOCK_DGRAM;
            continue;
        }
#endif

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

            backlog = 1;

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

        if (rp_strcmp(value[i].data, "reuseport") == 0) {
#if (RP_HAVE_REUSEPORT)
            ls->reuseport = 1;
            ls->bind = 1;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "reuseport is not supported "
                               "on this platform, ignored");
#endif
            continue;
        }

        if (rp_strcmp(value[i].data, "ssl") == 0) {
#if (RP_STREAM_SSL)
            rp_stream_ssl_conf_t  *sslcf;

            sslcf = rp_stream_conf_get_module_srv_conf(cf,
                                                        rp_stream_ssl_module);

            sslcf->listen = 1;
            sslcf->file = cf->conf_file->file.name.data;
            sslcf->line = cf->conf_file->line;

            ls->ssl = 1;

            continue;
#else
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "the \"ssl\" parameter requires "
                               "rp_stream_ssl_module");
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

        if (rp_strcmp(value[i].data, "proxy_protocol") == 0) {
            ls->proxy_protocol = 1;
            continue;
        }

        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "the invalid \"%V\" parameter", &value[i]);
        return RP_CONF_ERROR;
    }

    if (ls->type == SOCK_DGRAM) {
        if (backlog) {
            return "\"backlog\" parameter is incompatible with \"udp\"";
        }

#if (RP_STREAM_SSL)
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
        ls[n].wildcard = rp_inet_wildcard(ls[n].sockaddr);

        for (i = 0; i < cmcf->listen.nelts - u.naddrs + n; i++) {
            if (ls[n].type != als[i].type) {
                continue;
            }

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
rp_stream_core_resolver(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_core_srv_conf_t  *cscf = conf;

    rp_str_t  *value;

    if (cscf->resolver) {
        return "is duplicate";
    }

    value = cf->args->elts;

    cscf->resolver = rp_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (cscf->resolver == NULL) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
