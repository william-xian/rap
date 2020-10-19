
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>


static rap_int_t rap_stream_upstream_add_variables(rap_conf_t *cf);
static rap_int_t rap_stream_upstream_addr_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_upstream_response_time_variable(
    rap_stream_session_t *s, rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_upstream_bytes_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);

static char *rap_stream_upstream(rap_conf_t *cf, rap_command_t *cmd,
    void *dummy);
static char *rap_stream_upstream_server(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);
static void *rap_stream_upstream_create_main_conf(rap_conf_t *cf);
static char *rap_stream_upstream_init_main_conf(rap_conf_t *cf, void *conf);


static rap_command_t  rap_stream_upstream_commands[] = {

    { rap_string("upstream"),
      RAP_STREAM_MAIN_CONF|RAP_CONF_BLOCK|RAP_CONF_TAKE1,
      rap_stream_upstream,
      0,
      0,
      NULL },

    { rap_string("server"),
      RAP_STREAM_UPS_CONF|RAP_CONF_1MORE,
      rap_stream_upstream_server,
      RAP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rap_null_command
};


static rap_stream_module_t  rap_stream_upstream_module_ctx = {
    rap_stream_upstream_add_variables,     /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rap_stream_upstream_create_main_conf,  /* create main configuration */
    rap_stream_upstream_init_main_conf,    /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


rap_module_t  rap_stream_upstream_module = {
    RAP_MODULE_V1,
    &rap_stream_upstream_module_ctx,       /* module context */
    rap_stream_upstream_commands,          /* module directives */
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


static rap_stream_variable_t  rap_stream_upstream_vars[] = {

    { rap_string("upstream_addr"), NULL,
      rap_stream_upstream_addr_variable, 0,
      RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_bytes_sent"), NULL,
      rap_stream_upstream_bytes_variable, 0,
      RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_connect_time"), NULL,
      rap_stream_upstream_response_time_variable, 2,
      RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_first_byte_time"), NULL,
      rap_stream_upstream_response_time_variable, 1,
      RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_session_time"), NULL,
      rap_stream_upstream_response_time_variable, 0,
      RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("upstream_bytes_received"), NULL,
      rap_stream_upstream_bytes_variable, 1,
      RAP_STREAM_VAR_NOCACHEABLE, 0 },

      rap_stream_null_variable
};


static rap_int_t
rap_stream_upstream_add_variables(rap_conf_t *cf)
{
    rap_stream_variable_t  *var, *v;

    for (v = rap_stream_upstream_vars; v->name.len; v++) {
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
rap_stream_upstream_addr_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        len;
    rap_uint_t                    i;
    rap_stream_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    len = 0;
    state = s->upstream_states->elts;

    for (i = 0; i < s->upstream_states->nelts; i++) {
        if (state[i].peer) {
            len += state[i].peer->len;
        }

        len += 2;
    }

    p = rap_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->data = p;

    i = 0;

    for ( ;; ) {
        if (state[i].peer) {
            p = rap_cpymem(p, state[i].peer->data, state[i].peer->len);
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return RAP_OK;
}


static rap_int_t
rap_stream_upstream_bytes_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        len;
    rap_uint_t                    i;
    rap_stream_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    len = s->upstream_states->nelts * (RAP_OFF_T_LEN + 2);

    p = rap_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->data = p;

    i = 0;
    state = s->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            p = rap_sprintf(p, "%O", state[i].bytes_received);

        } else {
            p = rap_sprintf(p, "%O", state[i].bytes_sent);
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return RAP_OK;
}


static rap_int_t
rap_stream_upstream_response_time_variable(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        len;
    rap_uint_t                    i;
    rap_msec_int_t                ms;
    rap_stream_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    len = s->upstream_states->nelts * (RAP_TIME_T_LEN + 4 + 2);

    p = rap_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->data = p;

    i = 0;
    state = s->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            ms = state[i].first_byte_time;

        } else if (data == 2) {
            ms = state[i].connect_time;

        } else {
            ms = state[i].response_time;
        }

        if (ms != -1) {
            ms = rap_max(ms, 0);
            p = rap_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

        } else {
            *p++ = '-';
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return RAP_OK;
}


static char *
rap_stream_upstream(rap_conf_t *cf, rap_command_t *cmd, void *dummy)
{
    char                            *rv;
    void                            *mconf;
    rap_str_t                       *value;
    rap_url_t                        u;
    rap_uint_t                       m;
    rap_conf_t                       pcf;
    rap_stream_module_t             *module;
    rap_stream_conf_ctx_t           *ctx, *stream_ctx;
    rap_stream_upstream_srv_conf_t  *uscf;

    rap_memzero(&u, sizeof(rap_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    uscf = rap_stream_upstream_add(cf, &u, RAP_STREAM_UPSTREAM_CREATE
                                           |RAP_STREAM_UPSTREAM_WEIGHT
                                           |RAP_STREAM_UPSTREAM_MAX_CONNS
                                           |RAP_STREAM_UPSTREAM_MAX_FAILS
                                           |RAP_STREAM_UPSTREAM_FAIL_TIMEOUT
                                           |RAP_STREAM_UPSTREAM_DOWN
                                           |RAP_STREAM_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return RAP_CONF_ERROR;
    }


    ctx = rap_pcalloc(cf->pool, sizeof(rap_stream_conf_ctx_t));
    if (ctx == NULL) {
        return RAP_CONF_ERROR;
    }

    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = rap_pcalloc(cf->pool,
                                sizeof(void *) * rap_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return RAP_CONF_ERROR;
    }

    ctx->srv_conf[rap_stream_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;

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

    uscf->servers = rap_array_create(cf->pool, 4,
                                     sizeof(rap_stream_upstream_server_t));
    if (uscf->servers == NULL) {
        return RAP_CONF_ERROR;
    }


    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RAP_STREAM_UPS_CONF;

    rv = rap_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != RAP_CONF_OK) {
        return rv;
    }

    if (uscf->servers->nelts == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return RAP_CONF_ERROR;
    }

    return rv;
}


static char *
rap_stream_upstream_server(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_stream_upstream_srv_conf_t  *uscf = conf;

    time_t                         fail_timeout;
    rap_str_t                     *value, s;
    rap_url_t                      u;
    rap_int_t                      weight, max_conns, max_fails;
    rap_uint_t                     i;
    rap_stream_upstream_server_t  *us;

    us = rap_array_push(uscf->servers);
    if (us == NULL) {
        return RAP_CONF_ERROR;
    }

    rap_memzero(us, sizeof(rap_stream_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (rap_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & RAP_STREAM_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = rap_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == RAP_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "max_conns=", 10) == 0) {

            if (!(uscf->flags & RAP_STREAM_UPSTREAM_MAX_CONNS)) {
                goto not_supported;
            }

            max_conns = rap_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == RAP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & RAP_STREAM_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = rap_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == RAP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rap_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & RAP_STREAM_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = rap_parse_time(&s, 1);

            if (fail_timeout == (time_t) RAP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rap_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & RAP_STREAM_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (rap_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & RAP_STREAM_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    rap_memzero(&u, sizeof(rap_url_t));

    u.url = value[1];

    if (rap_parse_url(cf->pool, &u) != RAP_OK) {
        if (u.err) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return RAP_CONF_ERROR;
    }

    if (u.no_port) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "no port in upstream \"%V\"", &u.url);
        return RAP_CONF_ERROR;
    }

    us->name = u.url;
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_conns = max_conns;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return RAP_CONF_OK;

invalid:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return RAP_CONF_ERROR;

not_supported:

    rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return RAP_CONF_ERROR;
}


rap_stream_upstream_srv_conf_t *
rap_stream_upstream_add(rap_conf_t *cf, rap_url_t *u, rap_uint_t flags)
{
    rap_uint_t                        i;
    rap_stream_upstream_server_t     *us;
    rap_stream_upstream_srv_conf_t   *uscf, **uscfp;
    rap_stream_upstream_main_conf_t  *umcf;

    if (!(flags & RAP_STREAM_UPSTREAM_CREATE)) {

        if (rap_parse_url(cf->pool, u) != RAP_OK) {
            if (u->err) {
                rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || rap_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & RAP_STREAM_UPSTREAM_CREATE)
             && (uscfp[i]->flags & RAP_STREAM_UPSTREAM_CREATE))
        {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & RAP_STREAM_UPSTREAM_CREATE) && !u->no_port) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & RAP_STREAM_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

        if (uscfp[i]->port != u->port) {
            continue;
        }

        if (flags & RAP_STREAM_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
        }

        return uscfp[i];
    }

    uscf = rap_pcalloc(cf->pool, sizeof(rap_stream_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->no_port = u->no_port;

    if (u->naddrs == 1 && (u->port || u->family == AF_UNIX)) {
        uscf->servers = rap_array_create(cf->pool, 1,
                                         sizeof(rap_stream_upstream_server_t));
        if (uscf->servers == NULL) {
            return NULL;
        }

        us = rap_array_push(uscf->servers);
        if (us == NULL) {
            return NULL;
        }

        rap_memzero(us, sizeof(rap_stream_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    uscfp = rap_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


static void *
rap_stream_upstream_create_main_conf(rap_conf_t *cf)
{
    rap_stream_upstream_main_conf_t  *umcf;

    umcf = rap_pcalloc(cf->pool, sizeof(rap_stream_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (rap_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(rap_stream_upstream_srv_conf_t *))
        != RAP_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
rap_stream_upstream_init_main_conf(rap_conf_t *cf, void *conf)
{
    rap_stream_upstream_main_conf_t *umcf = conf;

    rap_uint_t                        i;
    rap_stream_upstream_init_pt       init;
    rap_stream_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream
                                         ? uscfp[i]->peer.init_upstream
                                         : rap_stream_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != RAP_OK) {
            return RAP_CONF_ERROR;
        }
    }

    return RAP_CONF_OK;
}
