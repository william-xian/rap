
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>


static rp_int_t rp_stream_upstream_add_variables(rp_conf_t *cf);
static rp_int_t rp_stream_upstream_addr_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_upstream_response_time_variable(
    rp_stream_session_t *s, rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_upstream_bytes_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);

static char *rp_stream_upstream(rp_conf_t *cf, rp_command_t *cmd,
    void *dummy);
static char *rp_stream_upstream_server(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);
static void *rp_stream_upstream_create_main_conf(rp_conf_t *cf);
static char *rp_stream_upstream_init_main_conf(rp_conf_t *cf, void *conf);


static rp_command_t  rp_stream_upstream_commands[] = {

    { rp_string("upstream"),
      RP_STREAM_MAIN_CONF|RP_CONF_BLOCK|RP_CONF_TAKE1,
      rp_stream_upstream,
      0,
      0,
      NULL },

    { rp_string("server"),
      RP_STREAM_UPS_CONF|RP_CONF_1MORE,
      rp_stream_upstream_server,
      RP_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      rp_null_command
};


static rp_stream_module_t  rp_stream_upstream_module_ctx = {
    rp_stream_upstream_add_variables,     /* preconfiguration */
    NULL,                                  /* postconfiguration */

    rp_stream_upstream_create_main_conf,  /* create main configuration */
    rp_stream_upstream_init_main_conf,    /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL                                   /* merge server configuration */
};


rp_module_t  rp_stream_upstream_module = {
    RP_MODULE_V1,
    &rp_stream_upstream_module_ctx,       /* module context */
    rp_stream_upstream_commands,          /* module directives */
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


static rp_stream_variable_t  rp_stream_upstream_vars[] = {

    { rp_string("upstream_addr"), NULL,
      rp_stream_upstream_addr_variable, 0,
      RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_bytes_sent"), NULL,
      rp_stream_upstream_bytes_variable, 0,
      RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_connect_time"), NULL,
      rp_stream_upstream_response_time_variable, 2,
      RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_first_byte_time"), NULL,
      rp_stream_upstream_response_time_variable, 1,
      RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_session_time"), NULL,
      rp_stream_upstream_response_time_variable, 0,
      RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("upstream_bytes_received"), NULL,
      rp_stream_upstream_bytes_variable, 1,
      RP_STREAM_VAR_NOCACHEABLE, 0 },

      rp_stream_null_variable
};


static rp_int_t
rp_stream_upstream_add_variables(rp_conf_t *cf)
{
    rp_stream_variable_t  *var, *v;

    for (v = rp_stream_upstream_vars; v->name.len; v++) {
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
rp_stream_upstream_addr_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        len;
    rp_uint_t                    i;
    rp_stream_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    len = 0;
    state = s->upstream_states->elts;

    for (i = 0; i < s->upstream_states->nelts; i++) {
        if (state[i].peer) {
            len += state[i].peer->len;
        }

        len += 2;
    }

    p = rp_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->data = p;

    i = 0;

    for ( ;; ) {
        if (state[i].peer) {
            p = rp_cpymem(p, state[i].peer->data, state[i].peer->len);
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return RP_OK;
}


static rp_int_t
rp_stream_upstream_bytes_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        len;
    rp_uint_t                    i;
    rp_stream_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    len = s->upstream_states->nelts * (RP_OFF_T_LEN + 2);

    p = rp_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->data = p;

    i = 0;
    state = s->upstream_states->elts;

    for ( ;; ) {

        if (data == 1) {
            p = rp_sprintf(p, "%O", state[i].bytes_received);

        } else {
            p = rp_sprintf(p, "%O", state[i].bytes_sent);
        }

        if (++i == s->upstream_states->nelts) {
            break;
        }

        *p++ = ',';
        *p++ = ' ';
    }

    v->len = p - v->data;

    return RP_OK;
}


static rp_int_t
rp_stream_upstream_response_time_variable(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char                       *p;
    size_t                        len;
    rp_uint_t                    i;
    rp_msec_int_t                ms;
    rp_stream_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (s->upstream_states == NULL || s->upstream_states->nelts == 0) {
        v->not_found = 1;
        return RP_OK;
    }

    len = s->upstream_states->nelts * (RP_TIME_T_LEN + 4 + 2);

    p = rp_pnalloc(s->connection->pool, len);
    if (p == NULL) {
        return RP_ERROR;
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
            ms = rp_max(ms, 0);
            p = rp_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000);

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

    return RP_OK;
}


static char *
rp_stream_upstream(rp_conf_t *cf, rp_command_t *cmd, void *dummy)
{
    char                            *rv;
    void                            *mconf;
    rp_str_t                       *value;
    rp_url_t                        u;
    rp_uint_t                       m;
    rp_conf_t                       pcf;
    rp_stream_module_t             *module;
    rp_stream_conf_ctx_t           *ctx, *stream_ctx;
    rp_stream_upstream_srv_conf_t  *uscf;

    rp_memzero(&u, sizeof(rp_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    uscf = rp_stream_upstream_add(cf, &u, RP_STREAM_UPSTREAM_CREATE
                                           |RP_STREAM_UPSTREAM_WEIGHT
                                           |RP_STREAM_UPSTREAM_MAX_CONNS
                                           |RP_STREAM_UPSTREAM_MAX_FAILS
                                           |RP_STREAM_UPSTREAM_FAIL_TIMEOUT
                                           |RP_STREAM_UPSTREAM_DOWN
                                           |RP_STREAM_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return RP_CONF_ERROR;
    }


    ctx = rp_pcalloc(cf->pool, sizeof(rp_stream_conf_ctx_t));
    if (ctx == NULL) {
        return RP_CONF_ERROR;
    }

    stream_ctx = cf->ctx;
    ctx->main_conf = stream_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = rp_pcalloc(cf->pool,
                                sizeof(void *) * rp_stream_max_module);
    if (ctx->srv_conf == NULL) {
        return RP_CONF_ERROR;
    }

    ctx->srv_conf[rp_stream_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;

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

    uscf->servers = rp_array_create(cf->pool, 4,
                                     sizeof(rp_stream_upstream_server_t));
    if (uscf->servers == NULL) {
        return RP_CONF_ERROR;
    }


    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = RP_STREAM_UPS_CONF;

    rv = rp_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != RP_CONF_OK) {
        return rv;
    }

    if (uscf->servers->nelts == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return RP_CONF_ERROR;
    }

    return rv;
}


static char *
rp_stream_upstream_server(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_stream_upstream_srv_conf_t  *uscf = conf;

    time_t                         fail_timeout;
    rp_str_t                     *value, s;
    rp_url_t                      u;
    rp_int_t                      weight, max_conns, max_fails;
    rp_uint_t                     i;
    rp_stream_upstream_server_t  *us;

    us = rp_array_push(uscf->servers);
    if (us == NULL) {
        return RP_CONF_ERROR;
    }

    rp_memzero(us, sizeof(rp_stream_upstream_server_t));

    value = cf->args->elts;

    weight = 1;
    max_conns = 0;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (rp_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & RP_STREAM_UPSTREAM_WEIGHT)) {
                goto not_supported;
            }

            weight = rp_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == RP_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "max_conns=", 10) == 0) {

            if (!(uscf->flags & RP_STREAM_UPSTREAM_MAX_CONNS)) {
                goto not_supported;
            }

            max_conns = rp_atoi(&value[i].data[10], value[i].len - 10);

            if (max_conns == RP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & RP_STREAM_UPSTREAM_MAX_FAILS)) {
                goto not_supported;
            }

            max_fails = rp_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == RP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rp_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & RP_STREAM_UPSTREAM_FAIL_TIMEOUT)) {
                goto not_supported;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = rp_parse_time(&s, 1);

            if (fail_timeout == (time_t) RP_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (rp_strcmp(value[i].data, "backup") == 0) {

            if (!(uscf->flags & RP_STREAM_UPSTREAM_BACKUP)) {
                goto not_supported;
            }

            us->backup = 1;

            continue;
        }

        if (rp_strcmp(value[i].data, "down") == 0) {

            if (!(uscf->flags & RP_STREAM_UPSTREAM_DOWN)) {
                goto not_supported;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    rp_memzero(&u, sizeof(rp_url_t));

    u.url = value[1];

    if (rp_parse_url(cf->pool, &u) != RP_OK) {
        if (u.err) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return RP_CONF_ERROR;
    }

    if (u.no_port) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "no port in upstream \"%V\"", &u.url);
        return RP_CONF_ERROR;
    }

    us->name = u.url;
    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_conns = max_conns;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return RP_CONF_OK;

invalid:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return RP_CONF_ERROR;

not_supported:

    rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                       "balancing method does not support parameter \"%V\"",
                       &value[i]);

    return RP_CONF_ERROR;
}


rp_stream_upstream_srv_conf_t *
rp_stream_upstream_add(rp_conf_t *cf, rp_url_t *u, rp_uint_t flags)
{
    rp_uint_t                        i;
    rp_stream_upstream_server_t     *us;
    rp_stream_upstream_srv_conf_t   *uscf, **uscfp;
    rp_stream_upstream_main_conf_t  *umcf;

    if (!(flags & RP_STREAM_UPSTREAM_CREATE)) {

        if (rp_parse_url(cf->pool, u) != RP_OK) {
            if (u->err) {
                rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || rp_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & RP_STREAM_UPSTREAM_CREATE)
             && (uscfp[i]->flags & RP_STREAM_UPSTREAM_CREATE))
        {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & RP_STREAM_UPSTREAM_CREATE) && !u->no_port) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & RP_STREAM_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

        if (uscfp[i]->port != u->port) {
            continue;
        }

        if (flags & RP_STREAM_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
        }

        return uscfp[i];
    }

    uscf = rp_pcalloc(cf->pool, sizeof(rp_stream_upstream_srv_conf_t));
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
        uscf->servers = rp_array_create(cf->pool, 1,
                                         sizeof(rp_stream_upstream_server_t));
        if (uscf->servers == NULL) {
            return NULL;
        }

        us = rp_array_push(uscf->servers);
        if (us == NULL) {
            return NULL;
        }

        rp_memzero(us, sizeof(rp_stream_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    uscfp = rp_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


static void *
rp_stream_upstream_create_main_conf(rp_conf_t *cf)
{
    rp_stream_upstream_main_conf_t  *umcf;

    umcf = rp_pcalloc(cf->pool, sizeof(rp_stream_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (rp_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(rp_stream_upstream_srv_conf_t *))
        != RP_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
rp_stream_upstream_init_main_conf(rp_conf_t *cf, void *conf)
{
    rp_stream_upstream_main_conf_t *umcf = conf;

    rp_uint_t                        i;
    rp_stream_upstream_init_pt       init;
    rp_stream_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream
                                         ? uscfp[i]->peer.init_upstream
                                         : rp_stream_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != RP_OK) {
            return RP_CONF_ERROR;
        }
    }

    return RP_CONF_OK;
}
