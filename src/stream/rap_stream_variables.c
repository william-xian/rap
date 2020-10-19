
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_stream.h>
#include <rap.h>

static rap_stream_variable_t *rap_stream_add_prefix_variable(rap_conf_t *cf,
    rap_str_t *name, rap_uint_t flags);

static rap_int_t rap_stream_variable_binary_remote_addr(
    rap_stream_session_t *s, rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_remote_addr(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_remote_port(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_proxy_protocol_addr(
    rap_stream_session_t *s, rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_proxy_protocol_port(
    rap_stream_session_t *s, rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_server_addr(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_server_port(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_bytes(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_session_time(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_status(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_connection(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);

static rap_int_t rap_stream_variable_rap_version(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_hostname(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_pid(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_msec(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_time_iso8601(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_time_local(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);
static rap_int_t rap_stream_variable_protocol(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data);


static rap_stream_variable_t  rap_stream_core_variables[] = {

    { rap_string("binary_remote_addr"), NULL,
      rap_stream_variable_binary_remote_addr, 0, 0, 0 },

    { rap_string("remote_addr"), NULL,
      rap_stream_variable_remote_addr, 0, 0, 0 },

    { rap_string("remote_port"), NULL,
      rap_stream_variable_remote_port, 0, 0, 0 },

    { rap_string("proxy_protocol_addr"), NULL,
      rap_stream_variable_proxy_protocol_addr,
      offsetof(rap_proxy_protocol_t, src_addr), 0, 0 },

    { rap_string("proxy_protocol_port"), NULL,
      rap_stream_variable_proxy_protocol_port,
      offsetof(rap_proxy_protocol_t, src_port), 0, 0 },

    { rap_string("proxy_protocol_server_addr"), NULL,
      rap_stream_variable_proxy_protocol_addr,
      offsetof(rap_proxy_protocol_t, dst_addr), 0, 0 },

    { rap_string("proxy_protocol_server_port"), NULL,
      rap_stream_variable_proxy_protocol_port,
      offsetof(rap_proxy_protocol_t, dst_port), 0, 0 },

    { rap_string("server_addr"), NULL,
      rap_stream_variable_server_addr, 0, 0, 0 },

    { rap_string("server_port"), NULL,
      rap_stream_variable_server_port, 0, 0, 0 },

    { rap_string("bytes_sent"), NULL, rap_stream_variable_bytes,
      0, 0, 0 },

    { rap_string("bytes_received"), NULL, rap_stream_variable_bytes,
      1, 0, 0 },

    { rap_string("session_time"), NULL, rap_stream_variable_session_time,
      0, RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("status"), NULL, rap_stream_variable_status,
      0, RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("connection"), NULL,
      rap_stream_variable_connection, 0, 0, 0 },

    { rap_string("rap_version"), NULL, rap_stream_variable_rap_version,
      0, 0, 0 },

    { rap_string("hostname"), NULL, rap_stream_variable_hostname,
      0, 0, 0 },

    { rap_string("pid"), NULL, rap_stream_variable_pid,
      0, 0, 0 },

    { rap_string("msec"), NULL, rap_stream_variable_msec,
      0, RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("time_iso8601"), NULL, rap_stream_variable_time_iso8601,
      0, RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("time_local"), NULL, rap_stream_variable_time_local,
      0, RAP_STREAM_VAR_NOCACHEABLE, 0 },

    { rap_string("protocol"), NULL,
      rap_stream_variable_protocol, 0, 0, 0 },

      rap_stream_null_variable
};


rap_stream_variable_value_t  rap_stream_variable_null_value =
    rap_stream_variable("");
rap_stream_variable_value_t  rap_stream_variable_true_value =
    rap_stream_variable("1");


static rap_uint_t  rap_stream_variable_depth = 100;


rap_stream_variable_t *
rap_stream_add_variable(rap_conf_t *cf, rap_str_t *name, rap_uint_t flags)
{
    rap_int_t                     rc;
    rap_uint_t                    i;
    rap_hash_key_t               *key;
    rap_stream_variable_t        *v;
    rap_stream_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    if (flags & RAP_STREAM_VAR_PREFIX) {
        return rap_stream_add_prefix_variable(cf, name, flags);
    }

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || rap_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & RAP_STREAM_VAR_CHANGEABLE)) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & RAP_STREAM_VAR_WEAK)) {
            v->flags &= ~RAP_STREAM_VAR_WEAK;
        }

        return v;
    }

    v = rap_palloc(cf->pool, sizeof(rap_stream_variable_t));
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = rap_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    rap_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    rc = rap_hash_add_key(cmcf->variables_keys, &v->name, v, 0);

    if (rc == RAP_ERROR) {
        return NULL;
    }

    if (rc == RAP_BUSY) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "conflicting variable name \"%V\"", name);
        return NULL;
    }

    return v;
}


static rap_stream_variable_t *
rap_stream_add_prefix_variable(rap_conf_t *cf, rap_str_t *name,
    rap_uint_t flags)
{
    rap_uint_t                    i;
    rap_stream_variable_t        *v;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);

    v = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || rap_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        v = &v[i];

        if (!(v->flags & RAP_STREAM_VAR_CHANGEABLE)) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & RAP_STREAM_VAR_WEAK)) {
            v->flags &= ~RAP_STREAM_VAR_WEAK;
        }

        return v;
    }

    v = rap_array_push(&cmcf->prefix_variables);
    if (v == NULL) {
        return NULL;
    }

    v->name.len = name->len;
    v->name.data = rap_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return NULL;
    }

    rap_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = flags;
    v->index = 0;

    return v;
}


rap_int_t
rap_stream_get_variable_index(rap_conf_t *cf, rap_str_t *name)
{
    rap_uint_t                    i;
    rap_stream_variable_t        *v;
    rap_stream_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return RAP_ERROR;
    }

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (rap_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(rap_stream_variable_t))
            != RAP_OK)
        {
            return RAP_ERROR;
        }

    } else {
        for (i = 0; i < cmcf->variables.nelts; i++) {
            if (name->len != v[i].name.len
                || rap_strncasecmp(name->data, v[i].name.data, name->len) != 0)
            {
                continue;
            }

            return i;
        }
    }

    v = rap_array_push(&cmcf->variables);
    if (v == NULL) {
        return RAP_ERROR;
    }

    v->name.len = name->len;
    v->name.data = rap_pnalloc(cf->pool, name->len);
    if (v->name.data == NULL) {
        return RAP_ERROR;
    }

    rap_strlow(v->name.data, name->data, name->len);

    v->set_handler = NULL;
    v->get_handler = NULL;
    v->data = 0;
    v->flags = 0;
    v->index = cmcf->variables.nelts - 1;

    return v->index;
}


rap_stream_variable_value_t *
rap_stream_get_indexed_variable(rap_stream_session_t *s, rap_uint_t index)
{
    rap_stream_variable_t        *v;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_get_module_main_conf(s, rap_stream_core_module);

    if (cmcf->variables.nelts <= index) {
        rap_log_error(RAP_LOG_ALERT, s->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (s->variables[index].not_found || s->variables[index].valid) {
        return &s->variables[index];
    }

    v = cmcf->variables.elts;

    if (rap_stream_variable_depth == 0) {
        rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    rap_stream_variable_depth--;

    if (v[index].get_handler(s, &s->variables[index], v[index].data)
        == RAP_OK)
    {
        rap_stream_variable_depth++;

        if (v[index].flags & RAP_STREAM_VAR_NOCACHEABLE) {
            s->variables[index].no_cacheable = 1;
        }

        return &s->variables[index];
    }

    rap_stream_variable_depth++;

    s->variables[index].valid = 0;
    s->variables[index].not_found = 1;

    return NULL;
}


rap_stream_variable_value_t *
rap_stream_get_flushed_variable(rap_stream_session_t *s, rap_uint_t index)
{
    rap_stream_variable_value_t  *v;

    v = &s->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return rap_stream_get_indexed_variable(s, index);
}


rap_stream_variable_value_t *
rap_stream_get_variable(rap_stream_session_t *s, rap_str_t *name,
    rap_uint_t key)
{
    size_t                        len;
    rap_uint_t                    i, n;
    rap_stream_variable_t        *v;
    rap_stream_variable_value_t  *vv;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_get_module_main_conf(s, rap_stream_core_module);

    v = rap_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & RAP_STREAM_VAR_INDEXED) {
            return rap_stream_get_flushed_variable(s, v->index);
        }

        if (rap_stream_variable_depth == 0) {
            rap_log_error(RAP_LOG_ERR, s->connection->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        rap_stream_variable_depth--;

        vv = rap_palloc(s->connection->pool,
                        sizeof(rap_stream_variable_value_t));

        if (vv && v->get_handler(s, vv, v->data) == RAP_OK) {
            rap_stream_variable_depth++;
            return vv;
        }

        rap_stream_variable_depth++;
        return NULL;
    }

    vv = rap_palloc(s->connection->pool, sizeof(rap_stream_variable_value_t));
    if (vv == NULL) {
        return NULL;
    }

    len = 0;

    v = cmcf->prefix_variables.elts;
    n = cmcf->prefix_variables.nelts;

    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len >= v[i].name.len && name->len > len
            && rap_strncmp(name->data, v[i].name.data, v[i].name.len) == 0)
        {
            len = v[i].name.len;
            n = i;
        }
    }

    if (n != cmcf->prefix_variables.nelts) {
        if (v[n].get_handler(s, vv, (uintptr_t) name) == RAP_OK) {
            return vv;
        }

        return NULL;
    }

    vv->not_found = 1;

    return vv;
}


static rap_int_t
rap_stream_variable_binary_remote_addr(rap_stream_session_t *s,
     rap_stream_variable_value_t *v, uintptr_t data)
{
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (s->connection->sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) s->connection->sockaddr;

        v->len = sizeof(struct in6_addr);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = sin6->sin6_addr.s6_addr;

        break;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
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

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_remote_addr(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    v->len = s->connection->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s->connection->addr_text.data;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_remote_port(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rap_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    port = rap_inet_get_port(s->connection->sockaddr);

    if (port > 0 && port < 65536) {
        v->len = rap_sprintf(v->data, "%ui", port) - v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_proxy_protocol_addr(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_str_t             *addr;
    rap_proxy_protocol_t  *pp;

    pp = s->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    addr = (rap_str_t *) ((char *) pp + data);

    v->len = addr->len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = addr->data;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_proxy_protocol_port(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_uint_t             port;
    rap_proxy_protocol_t  *pp;

    pp = s->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rap_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    port = *(in_port_t *) ((char *) pp + data);

    if (port > 0 && port < 65536) {
        v->len = rap_sprintf(v->data, "%ui", port) - v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_server_addr(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_str_t  str;
    u_char     addr[RAP_SOCKADDR_STRLEN];

    str.len = RAP_SOCKADDR_STRLEN;
    str.data = addr;

    if (rap_connection_local_sockaddr(s->connection, &str, 0) != RAP_OK) {
        return RAP_ERROR;
    }

    str.data = rap_pnalloc(s->connection->pool, str.len);
    if (str.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(str.data, addr, str.len);

    v->len = str.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = str.data;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_server_port(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    rap_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (rap_connection_local_sockaddr(s->connection, NULL, 0) != RAP_OK) {
        return RAP_ERROR;
    }

    v->data = rap_pnalloc(s->connection->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    port = rap_inet_get_port(s->connection->local_sockaddr);

    if (port > 0 && port < 65536) {
        v->len = rap_sprintf(v->data, "%ui", port) - v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_bytes(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(s->connection->pool, RAP_OFF_T_LEN);
    if (p == NULL) {
        return RAP_ERROR;
    }

    if (data == 1) {
        v->len = rap_sprintf(p, "%O", s->received) - p;

    } else {
        v->len = rap_sprintf(p, "%O", s->connection->sent) - p;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_session_time(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    rap_time_t      *tp;
    rap_msec_int_t   ms;

    p = rap_pnalloc(s->connection->pool, RAP_TIME_T_LEN + 4);
    if (p == NULL) {
        return RAP_ERROR;
    }

    tp = rap_timeofday();

    ms = (rap_msec_int_t)
             ((tp->sec - s->start_sec) * 1000 + (tp->msec - s->start_msec));
    ms = rap_max(ms, 0);

    v->len = rap_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_status(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    v->data = rap_pnalloc(s->connection->pool, RAP_INT_T_LEN);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(v->data, "%03ui", s->status) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_connection(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(s->connection->pool, RAP_ATOMIC_T_LEN);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(p, "%uA", s->connection->number) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_rap_version(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(RAP_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) RAP_VERSION;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_hostname(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    v->len = rap_cycle->hostname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = rap_cycle->hostname.data;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_pid(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(s->connection->pool, RAP_INT64_LEN);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(p, "%P", rap_pid) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_msec(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    rap_time_t  *tp;

    p = rap_pnalloc(s->connection->pool, RAP_TIME_T_LEN + 4);
    if (p == NULL) {
        return RAP_ERROR;
    }

    tp = rap_timeofday();

    v->len = rap_sprintf(p, "%T.%03M", tp->sec, tp->msec) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_time_iso8601(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(s->connection->pool, rap_cached_http_log_iso8601.len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(p, rap_cached_http_log_iso8601.data,
               rap_cached_http_log_iso8601.len);

    v->len = rap_cached_http_log_iso8601.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_time_local(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(s->connection->pool, rap_cached_http_log_time.len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(p, rap_cached_http_log_time.data, rap_cached_http_log_time.len);

    v->len = rap_cached_http_log_time.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_stream_variable_protocol(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    v->len = 3;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) (s->connection->type == SOCK_DGRAM ? "UDP" : "TCP");

    return RAP_OK;
}


void *
rap_stream_map_find(rap_stream_session_t *s, rap_stream_map_t *map,
    rap_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    rap_uint_t   key;

    len = match->len;

    if (len) {
        low = rap_pnalloc(s->connection->pool, len);
        if (low == NULL) {
            return NULL;
        }

    } else {
        low = NULL;
    }

    key = rap_hash_strlow(low, match->data, len);

    value = rap_hash_find_combined(&map->hash, key, low, len);
    if (value) {
        return value;
    }

#if (RAP_PCRE)

    if (len && map->nregex) {
        rap_int_t                n;
        rap_uint_t               i;
        rap_stream_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = rap_stream_regex_exec(s, reg[i].regex, match);

            if (n == RAP_OK) {
                return reg[i].value;
            }

            if (n == RAP_DECLINED) {
                continue;
            }

            /* RAP_ERROR */

            return NULL;
        }
    }

#endif

    return NULL;
}


#if (RAP_PCRE)

static rap_int_t
rap_stream_variable_not_found(rap_stream_session_t *s,
    rap_stream_variable_value_t *v, uintptr_t data)
{
    v->not_found = 1;
    return RAP_OK;
}


rap_stream_regex_t *
rap_stream_regex_compile(rap_conf_t *cf, rap_regex_compile_t *rc)
{
    u_char                       *p;
    size_t                        size;
    rap_str_t                     name;
    rap_uint_t                    i, n;
    rap_stream_variable_t        *v;
    rap_stream_regex_t           *re;
    rap_stream_regex_variable_t  *rv;
    rap_stream_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (rap_regex_compile(rc) != RAP_OK) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = rap_pcalloc(cf->pool, sizeof(rap_stream_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);
    cmcf->ncaptures = rap_max(cmcf->ncaptures, re->ncaptures);

    n = (rap_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = rap_palloc(rc->pool, n * sizeof(rap_stream_regex_variable_t));
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
        name.len = rap_strlen(name.data);

        v = rap_stream_add_variable(cf, &name, RAP_STREAM_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = rap_stream_get_variable_index(cf, &name);
        if (rv[i].index == RAP_ERROR) {
            return NULL;
        }

        v->get_handler = rap_stream_variable_not_found;

        p += size;
    }

    return re;
}


rap_int_t
rap_stream_regex_exec(rap_stream_session_t *s, rap_stream_regex_t *re,
    rap_str_t *str)
{
    rap_int_t                     rc, index;
    rap_uint_t                    i, n, len;
    rap_stream_variable_value_t  *vv;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_get_module_main_conf(s, rap_stream_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (s->captures == NULL) {
            s->captures = rap_palloc(s->connection->pool, len * sizeof(int));
            if (s->captures == NULL) {
                return RAP_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = rap_regex_exec(re->regex, str, s->captures, len);

    if (rc == RAP_REGEX_NO_MATCHED) {
        return RAP_DECLINED;
    }

    if (rc < 0) {
        rap_log_error(RAP_LOG_ALERT, s->connection->log, 0,
                      rap_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, str, &re->name);
        return RAP_ERROR;
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

#if (RAP_DEBUG)
        {
        rap_stream_variable_t  *v;

        v = cmcf->variables.elts;

        rap_log_debug2(RAP_LOG_DEBUG_STREAM, s->connection->log, 0,
                       "stream regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    s->ncaptures = rc * 2;
    s->captures_data = str->data;

    return RAP_OK;
}

#endif


rap_int_t
rap_stream_variables_add_core_vars(rap_conf_t *cf)
{
    rap_stream_variable_t        *cv, *v;
    rap_stream_core_main_conf_t  *cmcf;

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);

    cmcf->variables_keys = rap_pcalloc(cf->temp_pool,
                                       sizeof(rap_hash_keys_arrays_t));
    if (cmcf->variables_keys == NULL) {
        return RAP_ERROR;
    }

    cmcf->variables_keys->pool = cf->pool;
    cmcf->variables_keys->temp_pool = cf->pool;

    if (rap_hash_keys_array_init(cmcf->variables_keys, RAP_HASH_SMALL)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    if (rap_array_init(&cmcf->prefix_variables, cf->pool, 8,
                       sizeof(rap_stream_variable_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    for (cv = rap_stream_core_variables; cv->name.len; cv++) {
        v = rap_stream_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return RAP_ERROR;
        }

        *v = *cv;
    }

    return RAP_OK;
}


rap_int_t
rap_stream_variables_init_vars(rap_conf_t *cf)
{
    size_t                        len;
    rap_uint_t                    i, n;
    rap_hash_key_t               *key;
    rap_hash_init_t               hash;
    rap_stream_variable_t        *v, *av, *pv;
    rap_stream_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed stream variables */

    cmcf = rap_stream_conf_get_module_main_conf(cf, rap_stream_core_module);

    v = cmcf->variables.elts;
    pv = cmcf->prefix_variables.elts;
    key = cmcf->variables_keys->keys.elts;

    for (i = 0; i < cmcf->variables.nelts; i++) {

        for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {

            av = key[n].value;

            if (v[i].name.len == key[n].key.len
                && rap_strncmp(v[i].name.data, key[n].key.data, v[i].name.len)
                   == 0)
            {
                v[i].get_handler = av->get_handler;
                v[i].data = av->data;

                av->flags |= RAP_STREAM_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                if (av->get_handler == NULL
                    || (av->flags & RAP_STREAM_VAR_WEAK))
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
                && rap_strncmp(v[i].name.data, pv[n].name.data, pv[n].name.len)
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
            rap_log_error(RAP_LOG_EMERG, cf->log, 0,
                          "unknown \"%V\" variable", &v[i].name);
            return RAP_ERROR;
        }

    next:
        continue;
    }


    for (n = 0; n < cmcf->variables_keys->keys.nelts; n++) {
        av = key[n].value;

        if (av->flags & RAP_STREAM_VAR_NOHASH) {
            key[n].key.data = NULL;
        }
    }


    hash.hash = &cmcf->variables_hash;
    hash.key = rap_hash_key;
    hash.max_size = cmcf->variables_hash_max_size;
    hash.bucket_size = cmcf->variables_hash_bucket_size;
    hash.name = "variables_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (rap_hash_init(&hash, cmcf->variables_keys->keys.elts,
                      cmcf->variables_keys->keys.nelts)
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    cmcf->variables_keys = NULL;

    return RAP_OK;
}
