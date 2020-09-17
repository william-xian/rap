
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_stream.h>
#include <rap.h>

static rp_stream_variable_t *rp_stream_add_prefix_variable(rp_conf_t *cf,
    rp_str_t *name, rp_uint_t flags);

static rp_int_t rp_stream_variable_binary_remote_addr(
    rp_stream_session_t *s, rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_remote_addr(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_remote_port(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_proxy_protocol_addr(
    rp_stream_session_t *s, rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_proxy_protocol_port(
    rp_stream_session_t *s, rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_server_addr(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_server_port(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_bytes(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_session_time(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_status(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_connection(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);

static rp_int_t rp_stream_variable_rap_version(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_hostname(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_pid(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_msec(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_time_iso8601(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_time_local(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);
static rp_int_t rp_stream_variable_protocol(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data);


static rp_stream_variable_t  rp_stream_core_variables[] = {

    { rp_string("binary_remote_addr"), NULL,
      rp_stream_variable_binary_remote_addr, 0, 0, 0 },

    { rp_string("remote_addr"), NULL,
      rp_stream_variable_remote_addr, 0, 0, 0 },

    { rp_string("remote_port"), NULL,
      rp_stream_variable_remote_port, 0, 0, 0 },

    { rp_string("proxy_protocol_addr"), NULL,
      rp_stream_variable_proxy_protocol_addr,
      offsetof(rp_proxy_protocol_t, src_addr), 0, 0 },

    { rp_string("proxy_protocol_port"), NULL,
      rp_stream_variable_proxy_protocol_port,
      offsetof(rp_proxy_protocol_t, src_port), 0, 0 },

    { rp_string("proxy_protocol_server_addr"), NULL,
      rp_stream_variable_proxy_protocol_addr,
      offsetof(rp_proxy_protocol_t, dst_addr), 0, 0 },

    { rp_string("proxy_protocol_server_port"), NULL,
      rp_stream_variable_proxy_protocol_port,
      offsetof(rp_proxy_protocol_t, dst_port), 0, 0 },

    { rp_string("server_addr"), NULL,
      rp_stream_variable_server_addr, 0, 0, 0 },

    { rp_string("server_port"), NULL,
      rp_stream_variable_server_port, 0, 0, 0 },

    { rp_string("bytes_sent"), NULL, rp_stream_variable_bytes,
      0, 0, 0 },

    { rp_string("bytes_received"), NULL, rp_stream_variable_bytes,
      1, 0, 0 },

    { rp_string("session_time"), NULL, rp_stream_variable_session_time,
      0, RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("status"), NULL, rp_stream_variable_status,
      0, RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("connection"), NULL,
      rp_stream_variable_connection, 0, 0, 0 },

    { rp_string("rap_version"), NULL, rp_stream_variable_rap_version,
      0, 0, 0 },

    { rp_string("hostname"), NULL, rp_stream_variable_hostname,
      0, 0, 0 },

    { rp_string("pid"), NULL, rp_stream_variable_pid,
      0, 0, 0 },

    { rp_string("msec"), NULL, rp_stream_variable_msec,
      0, RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("time_iso8601"), NULL, rp_stream_variable_time_iso8601,
      0, RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("time_local"), NULL, rp_stream_variable_time_local,
      0, RP_STREAM_VAR_NOCACHEABLE, 0 },

    { rp_string("protocol"), NULL,
      rp_stream_variable_protocol, 0, 0, 0 },

      rp_stream_null_variable
};


rp_stream_variable_value_t  rp_stream_variable_null_value =
    rp_stream_variable("");
rp_stream_variable_value_t  rp_stream_variable_true_value =
    rp_stream_variable("1");


static rp_uint_t  rp_stream_variable_depth = 100;


rp_stream_variable_t *
rp_stream_add_variable(rp_conf_t *cf, rp_str_t *name, rp_uint_t flags)
{
    rp_int_t                     rc;
    rp_uint_t                    i;
    rp_hash_key_t               *key;
    rp_stream_variable_t        *v;
    rp_stream_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    if (flags & RP_STREAM_VAR_PREFIX) {
        return rp_stream_add_prefix_variable(cf, name, flags);
    }

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || rp_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & RP_STREAM_VAR_CHANGEABLE)) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & RP_STREAM_VAR_WEAK)) {
            v->flags &= ~RP_STREAM_VAR_WEAK;
        }

        return v;
    }

    v = rp_palloc(cf->pool, sizeof(rp_stream_variable_t));
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = rp_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    rp_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    rc = rp_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == RP_ERROR) {
        return NULL;
    }

    if (rc == RP_BUSY) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }

    return v;
}


static rp_stream_variable_t *
rp_stream_add_prefix_variable(rp_conf_t *cf, rp_str_t *name,
    rp_uint_t flags)
{
    rp_uint_t                    i;
    rp_stream_variable_t        *v;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    v = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || rp_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        v = &v[i];

        if (!(v->flags & RP_STREAM_VAR_CHANGEABLE)) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & RP_STREAM_VAR_WEAK)) {
            v->flags &= ~RP_STREAM_VAR_WEAK;
        }

        return v;
    }

    v = rp_array_push(&cmcf->prefix_variables);
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = rp_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    rp_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    return v;
}


rp_int_t
rp_stream_get_variable_index(rp_conf_t *cf, rp_str_t *name)
{
    rp_uint_t                    i;
    rp_stream_variable_t        *v;
    rp_stream_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return RP_ERROR;
    }

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (rp_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(rp_stream_variable_t))
            != RP_OK)
        {
            return RP_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || rp_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    v = rp_array_push(&cmcf->variables);
    if (v == NULL) {
        return RP_ERROR;
    }

    v->name.len = name->len;
    v->name.data = rp_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return RP_ERROR;
    }

    rp_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    return v->index;
}


rp_stream_variable_value_t *
rp_stream_get_indexed_variable(rp_stream_session_t *s, rp_uint_t index)
{
    rp_stream_variable_t        *v;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_get_module_main_conf(s, rp_stream_core_module);

    if (cmcf->variables.nelts <= index) {
        rp_log_error(RP_LOG_ALERT, s->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (s->variables[index].not_found || s->variables[index].valid) {
        return &s->variables[index];
    }

    v = cmcf->variables.elts;

    if (rp_stream_variable_depth == 0) {
        rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    rp_stream_variable_depth--;

    if (v[index].get_handler(s, &s->variables[index], v[index].data)
        == RP_OK)
    {
        rp_stream_variable_depth++;

        if (v[index].flags & RP_STREAM_VAR_NOCACHEABLE) {
            s->variables[index].no_cacheable = 1;
        }

        return &s->variables[index];
    }

    rp_stream_variable_depth++;

    s->variables[index].valid = 0;
    s->variables[index].not_found = 1;

    return NULL;
}


rp_stream_variable_value_t *
rp_stream_get_flushed_variable(rp_stream_session_t *s, rp_uint_t index)
{
    rp_stream_variable_value_t  *v;

    v = &s->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return rp_stream_get_indexed_variable(s, index);
}


rp_stream_variable_value_t *
rp_stream_get_variable(rp_stream_session_t *s, rp_str_t *name,
    rp_uint_t key)
{
    size_t                        len;
    rp_uint_t                    i, n;
    rp_stream_variable_t        *v;
    rp_stream_variable_value_t  *vv;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_get_module_main_conf(s, rp_stream_core_module);

    v = rp_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & RP_STREAM_VAR_INDEXED) {
            return rp_stream_get_flushed_variable(s, v->index);
        }

        if (rp_stream_variable_depth == 0) {
            rp_log_error(RP_LOG_ERR, s->connection->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        rp_stream_variable_depth--;

        vv = rp_palloc(s->connection->pool,
                        sizeof(rp_stream_variable_value_t));

        if (vv && v->get_handler(s, vv, v->data) == RP_OK) {
            rp_stream_variable_depth++;
            return vv;
        }

        rp_stream_variable_depth++;
        return NULL;
    }

    vv = rp_palloc(s->connection->pool, sizeof(rp_stream_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    len = 0;

    v = cmcf->prefix_variables.elts;
    n = cmcf->prefix_variables.nelts;

    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len >= v[i].name.len && name->len > len
            && rp_strncmp(name->data, v[i].name.data, v[i].name.len) == 0)
        {
            len = v[i].name.len;
            n = i;
        }
    }

    if (n != cmcf->prefix_variables.nelts) {
        if (v[n].get_handler(s, vv, (uintptr_t) name) == RP_OK) {
            return vv;
        }

        return NULL;
    }

    vv->not_found = 1;

    return vv;
}


static rp_int_t
rp_stream_variable_binary_remote_addr(rp_stream_session_t *s,
     rp_stream_variable_value_t *v, uintptr_t data)
{
    struct sockaddr_in   *sin;
#if (RP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (s->connection->sockaddr->sa_family) {

#if (RP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;

        v->len = sizeof(struct in6_addr);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = sin6->sin6_addr.s6_addr;

        break;
#endif

#if (RP_HAVE_UNIX_DOMAIN)
    case AF_UNIX:

        v->len = s->connection->addr_text.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->connection->addr_text.data;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) s->connection->sockaddr;

        v->len = sizeof(in_addr_t);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) &sin->sin_addr;

        break;
    }

    return RP_OK;
}


static rp_int_t
rp_stream_variable_remote_addr(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    v->len = s->connection->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s->connection->addr_text.data;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_remote_port(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rp_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    port = rp_inet_get_port(s->connection->sockaddr);

    if (port > 0 && port < 65536) {
        v->len = rp_sprintf(v->data, "%ui", port) - v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_stream_variable_proxy_protocol_addr(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_str_t             *addr;
    rp_proxy_protocol_t  *pp;

    pp = s->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return RP_OK;
    }

    addr = (rp_str_t *) ((char *) pp + data);

    v->len = addr->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr->data;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_proxy_protocol_port(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_uint_t             port;
    rp_proxy_protocol_t  *pp;

    pp = s->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return RP_OK;
    }

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rp_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    port = *(in_port_t *) ((char *) pp + data);

    if (port > 0 && port < 65536) {
        v->len = rp_sprintf(v->data, "%ui", port) - v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_stream_variable_server_addr(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_str_t  str;
    u_char     addr[RP_SOCKADDR_STRLEN];

    str.len = RP_SOCKADDR_STRLEN;
    str.data = addr;

    if (rp_connection_local_sockaddr(s->connection, &str, 0) != RP_OK) {
        return RP_ERROR;
    }

    str.data = rp_pnalloc(s->connection->pool, str.len);
    if (str.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(str.data, addr, str.len);

    v->len = str.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = str.data;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_server_port(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    rp_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (rp_connection_local_sockaddr(s->connection, NULL, 0) != RP_OK) {
        return RP_ERROR;
    }

    v->data = rp_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    port = rp_inet_get_port(s->connection->local_sockaddr);

    if (port > 0 && port < 65536) {
        v->len = rp_sprintf(v->data, "%ui", port) - v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_stream_variable_bytes(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(s->connection->pool, RP_OFF_T_LEN);
    if (p == NULL) {
        return RP_ERROR;
    }

    if (data == 1) {
        v->len = rp_sprintf(p, "%O", s->received) - p;

    } else {
        v->len = rp_sprintf(p, "%O", s->connection->sent) - p;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_session_time(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    rp_time_t      *tp;
    rp_msec_int_t   ms;

    p = rp_pnalloc(s->connection->pool, RP_TIME_T_LEN + 4);
    if (p == NULL) {
        return RP_ERROR;
    }

    tp = rp_timeofday();

    ms = (rp_msec_int_t)
             ((tp->sec - s->start_sec) * 1000 + (tp->msec - s->start_msec));
    ms = rp_max(ms, 0);

    v->len = rp_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_status(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    v->data = rp_pnalloc(s->connection->pool, RP_INT_T_LEN);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    v->len = rp_sprintf(v->data, "%03ui", s->status) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_connection(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(s->connection->pool, RP_ATOMIC_T_LEN);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->len = rp_sprintf(p, "%uA", s->connection->number) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_rap_version(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(RAP_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) RAP_VERSION;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_hostname(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    v->len = rp_cycle->hostname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = rp_cycle->hostname.data;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_pid(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(s->connection->pool, RP_INT64_LEN);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->len = rp_sprintf(p, "%P", rp_pid) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_msec(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    rp_time_t  *tp;

    p = rp_pnalloc(s->connection->pool, RP_TIME_T_LEN + 4);
    if (p == NULL) {
        return RP_ERROR;
    }

    tp = rp_timeofday();

    v->len = rp_sprintf(p, "%T.%03M", tp->sec, tp->msec) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_time_iso8601(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(s->connection->pool, rp_cached_http_log_iso8601.len);
    if (p == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(p, rp_cached_http_log_iso8601.data,
               rp_cached_http_log_iso8601.len);

    v->len = rp_cached_http_log_iso8601.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_time_local(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(s->connection->pool, rp_cached_http_log_time.len);
    if (p == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(p, rp_cached_http_log_time.data, rp_cached_http_log_time.len);

    v->len = rp_cached_http_log_time.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_stream_variable_protocol(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    v->len = 3;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) (s->connection->type == SOCK_DGRAM ? "UDP" : "TCP");

    return RP_OK;
}


void *
rp_stream_map_find(rp_stream_session_t *s, rp_stream_map_t *map,
    rp_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    rp_uint_t   key;

    len = match->len;

    if (len) {
        low = rp_pnalloc(s->connection->pool, len);
        if (low == NULL) {
            return NULL;
        }

    } else {
        low = NULL;
    }

    key = rp_hash_strlow(low, match->data, len);

    value = rp_hash_find_combined(&map->hash, key, low, len);
    if (value) {
        return value;
    }

#if (RP_PCRE)

    if (len && map->nregex) {
        rp_int_t                n;
        rp_uint_t               i;
        rp_stream_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = rp_stream_regex_exec(s, reg[i].regex, match);

            if (n == RP_OK) {
                return reg[i].value;
            }

            if (n == RP_DECLINED) {
                continue;
            }

            /* RP_ERROR */

            return NULL;
        }
    }

#endif

    return NULL;
}


#if (RP_PCRE)

static rp_int_t
rp_stream_variable_not_found(rp_stream_session_t *s,
    rp_stream_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;
    return RP_OK;
}


rp_stream_regex_t *
rp_stream_regex_compile(rp_conf_t *cf, rp_regex_compile_t *rc)
{
    u_char                       *p;
    size_t                        size;
    rp_str_t                     name;
    rp_uint_t                    i, n;
    rp_stream_variable_t        *v;
    rp_stream_regex_t           *re;
    rp_stream_regex_variable_t  *rv;
    rp_stream_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (rp_regex_compile(rc) != RP_OK) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = rp_pcalloc(cf->pool, sizeof(rp_stream_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);
    cmcf->ncaptures = rp_max(cmcf->ncaptures, re->ncaptures);

    n = (rp_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = rp_palloc(rc->pool, n * sizeof(rp_stream_regex_variable_t));
    if (rv == NULL) {
        return NULL;
    }

    re->variables = rv;
    re->nvariables = n;

    size = rc->name_size;
    p = rc->names;

    for (i = 0; i < n; i++) {
        rv[i].capture = 2 * ((p[0] << 8) + p[1]);

        name.data = &p[2];
        name.len = rp_strlen(name.data);

        v = rp_stream_add_variable(cf, &name, RP_STREAM_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = rp_stream_get_variable_index(cf, &name);
        if (rv[i].index == RP_ERROR) {
            return NULL;
        }

        v->get_handler = rp_stream_variable_not_found;

        p += size;
    }

    return re;
}


rp_int_t
rp_stream_regex_exec(rp_stream_session_t *s, rp_stream_regex_t *re,
    rp_str_t *str)
{
    rp_int_t                     rc, index;
    rp_uint_t                    i, n, len;
    rp_stream_variable_value_t  *vv;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_get_module_main_conf(s, rp_stream_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (s->captures == NULL) {
            s->captures = rp_palloc(s->connection->pool, len * sizeof(int));
            if (s->captures == NULL) {
                return RP_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = rp_regex_exec(re->regex, str, s->captures, len);

    if (rc == RP_REGEX_NO_MATCHED) {
        return RP_DECLINED;
    }

    if (rc < 0) {
        rp_log_error(RP_LOG_ALERT, s->connection->log, 0,
                      rp_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, str, &re->name);
        return RP_ERROR;
    }

    for (i = 0; i < re->nvariables; i++) {

        n = re->variables[i].capture;
        index = re->variables[i].index;
        vv = &s->variables[index];

        vv->len = s->captures[n + 1] - s->captures[n];
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = &str->data[s->captures[n]];

#if (RP_DEBUG)
        {
        rp_stream_variable_t  *v;

        v = cmcf->variables.elts;

        rp_log_debug2(RP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    s->ncaptures = rc * 2;
    s->captures_data = str->data;

    return RP_OK;
}

#endif


rp_int_t
rp_stream_variables_add_core_vars(rp_conf_t *cf)
{
    rp_stream_variable_t        *cv, *v;
    rp_stream_core_main_conf_t  *cmcf;

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    cmcf->variables_keys = rp_pcalloc(cf->temp_pool,
                                       sizeof(rp_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return RP_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;

    if (rp_hash_keys_array_init(cmcf->variables_keys, RP_HASH_SMALL)
        != RP_OK)
    {
        return RP_ERROR;
    }

    if (rp_array_init(&cmcf->prefix_variables, cf->pool, 8,
                       sizeof(rp_stream_variable_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    for (cv = rp_stream_core_variables; cv->name.len; cv++) {
        v = rp_stream_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return RP_ERROR;
        }

        *v = *cv;
    }

    return RP_OK;
}


rp_int_t
rp_stream_variables_init_vars(rp_conf_t *cf)
{
    size_t                        len;
    rp_uint_t                    i, n;
    rp_hash_key_t               *key;
    rp_hash_init_t               hash;
    rp_stream_variable_t        *v, *av, *pv;
    rp_stream_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed stream variables */

    cmcf = rp_stream_conf_get_module_main_conf(cf, rp_stream_core_module);

    v = cmcf->variables.elts;
    pv = cmcf->prefix_variables.elts;
    key = cmcf->variables_keys->keys.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (v[i].name.len == key[n].key.len
                && rp_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;

                av->flags |= RP_STREAM_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                if (av->get_handler == NULL
                    || (av->flags & RP_STREAM_VAR_WEAK))
                {
                    break;
                }

                goto next;
            }
        }

        len = 0;
        av = NULL;

        for (n = 0; n < cmcf->prefix_variables.nelts; n++) {
            if (v[i].name.len >= pv[n].name.len && v[i].name.len > len
                && rp_strncmp(v[i].name.data, pv[n].name.data, pv[n].name.len)
                   == 0)
            {
                av = &pv[n];
                len = pv[n].name.len;
            }
        }

        if (av) {
            v[i].get_handler = av->get_handler;
            v[i].data = (uintptr_t) &v[i].name;
            v[i].flags = av->flags;

            goto next;
         }

        if (v[i].get_handler == NULL) {
            rp_log_error(RP_LOG_EMERG, cf->log, 0,
                          "unknown \"%V\" variable", &v[i].name);
            return RP_ERROR;
        }

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & RP_STREAM_VAR_NOHASH) {
            key[n].key.data = NULL;
        }
    }


    hash.hash = &cmcf->variables_hash;
    hash.key = rp_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (rp_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts)
        != RP_OK)
    {
        return RP_ERROR;
    }

    cmcf->variables_keys = NULL;

    return RP_OK;
}
