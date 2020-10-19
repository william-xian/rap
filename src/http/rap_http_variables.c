
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap.h>


static rap_http_variable_t *rap_http_add_prefix_variable(rap_conf_t *cf,
    rap_str_t *name, rap_uint_t flags);

static rap_int_t rap_http_variable_request(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
#if 0
static void rap_http_variable_request_set(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
#endif
static rap_int_t rap_http_variable_request_get_size(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_header(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);

static rap_int_t rap_http_variable_cookies(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_headers(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_headers_internal(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data, u_char sep);

static rap_int_t rap_http_variable_unknown_header_in(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_unknown_header_out(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_unknown_trailer_out(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_request_line(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_cookie(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_argument(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
#if (RAP_HAVE_TCP_INFO)
static rap_int_t rap_http_variable_tcpinfo(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
#endif

static rap_int_t rap_http_variable_content_length(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_host(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_binary_remote_addr(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_remote_addr(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_remote_port(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_proxy_protocol_addr(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_proxy_protocol_port(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_server_addr(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_server_port(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_scheme(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_https(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static void rap_http_variable_set_args(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_is_args(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_document_root(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_realpath_root(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_request_filename(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_server_name(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_request_method(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_remote_user(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_bytes_sent(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_body_bytes_sent(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_pipe(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_request_completion(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_request_body(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_request_body_file(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_request_length(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_request_time(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_request_id(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_status(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);

static rap_int_t rap_http_variable_sent_content_type(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_sent_content_length(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_sent_location(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_sent_last_modified(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_sent_connection(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_sent_keep_alive(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_sent_transfer_encoding(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static void rap_http_variable_set_limit_rate(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);

static rap_int_t rap_http_variable_connection(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_connection_requests(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);

static rap_int_t rap_http_variable_rap_version(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_hostname(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_pid(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_msec(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_time_iso8601(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);
static rap_int_t rap_http_variable_time_local(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data);

/*
 * TODO:
 *     Apache CGI: AUTH_TYPE, PATH_INFO (null), PATH_TRANSLATED
 *                 REMOTE_HOST (null), REMOTE_IDENT (null),
 *                 SERVER_SOFTWARE
 *
 *     Apache SSI: DOCUMENT_NAME, LAST_MODIFIED, USER_NAME (file owner)
 */

/*
 * the $http_host, $http_user_agent, $http_referer, and $http_via
 * variables may be handled by generic
 * rap_http_variable_unknown_header_in(), but for performance reasons
 * they are handled using dedicated entries
 */

static rap_http_variable_t  rap_http_core_variables[] = {

    { rap_string("http_host"), NULL, rap_http_variable_header,
      offsetof(rap_http_request_t, headers_in.host), 0, 0 },

    { rap_string("http_user_agent"), NULL, rap_http_variable_header,
      offsetof(rap_http_request_t, headers_in.user_agent), 0, 0 },

    { rap_string("http_referer"), NULL, rap_http_variable_header,
      offsetof(rap_http_request_t, headers_in.referer), 0, 0 },

#if (RAP_HTTP_GZIP)
    { rap_string("http_via"), NULL, rap_http_variable_header,
      offsetof(rap_http_request_t, headers_in.via), 0, 0 },
#endif

#if (RAP_HTTP_X_FORWARDED_FOR)
    { rap_string("http_x_forwarded_for"), NULL, rap_http_variable_headers,
      offsetof(rap_http_request_t, headers_in.x_forwarded_for), 0, 0 },
#endif

    { rap_string("http_cookie"), NULL, rap_http_variable_cookies,
      offsetof(rap_http_request_t, headers_in.cookies), 0, 0 },

    { rap_string("content_length"), NULL, rap_http_variable_content_length,
      0, 0, 0 },

    { rap_string("content_type"), NULL, rap_http_variable_header,
      offsetof(rap_http_request_t, headers_in.content_type), 0, 0 },

    { rap_string("host"), NULL, rap_http_variable_host, 0, 0, 0 },

    { rap_string("binary_remote_addr"), NULL,
      rap_http_variable_binary_remote_addr, 0, 0, 0 },

    { rap_string("remote_addr"), NULL, rap_http_variable_remote_addr, 0, 0, 0 },

    { rap_string("remote_port"), NULL, rap_http_variable_remote_port, 0, 0, 0 },

    { rap_string("proxy_protocol_addr"), NULL,
      rap_http_variable_proxy_protocol_addr,
      offsetof(rap_proxy_protocol_t, src_addr), 0, 0 },

    { rap_string("proxy_protocol_port"), NULL,
      rap_http_variable_proxy_protocol_port,
      offsetof(rap_proxy_protocol_t, src_port), 0, 0 },

    { rap_string("proxy_protocol_server_addr"), NULL,
      rap_http_variable_proxy_protocol_addr,
      offsetof(rap_proxy_protocol_t, dst_addr), 0, 0 },

    { rap_string("proxy_protocol_server_port"), NULL,
      rap_http_variable_proxy_protocol_port,
      offsetof(rap_proxy_protocol_t, dst_port), 0, 0 },

    { rap_string("server_addr"), NULL, rap_http_variable_server_addr, 0, 0, 0 },

    { rap_string("server_port"), NULL, rap_http_variable_server_port, 0, 0, 0 },

    { rap_string("server_protocol"), NULL, rap_http_variable_request,
      offsetof(rap_http_request_t, http_protocol), 0, 0 },

    { rap_string("scheme"), NULL, rap_http_variable_scheme, 0, 0, 0 },

    { rap_string("https"), NULL, rap_http_variable_https, 0, 0, 0 },

    { rap_string("request_uri"), NULL, rap_http_variable_request,
      offsetof(rap_http_request_t, unparsed_uri), 0, 0 },

    { rap_string("uri"), NULL, rap_http_variable_request,
      offsetof(rap_http_request_t, uri),
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("document_uri"), NULL, rap_http_variable_request,
      offsetof(rap_http_request_t, uri),
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("request"), NULL, rap_http_variable_request_line, 0, 0, 0 },

    { rap_string("document_root"), NULL,
      rap_http_variable_document_root, 0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("realpath_root"), NULL,
      rap_http_variable_realpath_root, 0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("query_string"), NULL, rap_http_variable_request,
      offsetof(rap_http_request_t, args),
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("args"),
      rap_http_variable_set_args,
      rap_http_variable_request,
      offsetof(rap_http_request_t, args),
      RAP_HTTP_VAR_CHANGEABLE|RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("is_args"), NULL, rap_http_variable_is_args,
      0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("request_filename"), NULL,
      rap_http_variable_request_filename, 0,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("server_name"), NULL, rap_http_variable_server_name, 0, 0, 0 },

    { rap_string("request_method"), NULL,
      rap_http_variable_request_method, 0,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("remote_user"), NULL, rap_http_variable_remote_user, 0, 0, 0 },

    { rap_string("bytes_sent"), NULL, rap_http_variable_bytes_sent,
      0, 0, 0 },

    { rap_string("body_bytes_sent"), NULL, rap_http_variable_body_bytes_sent,
      0, 0, 0 },

    { rap_string("pipe"), NULL, rap_http_variable_pipe,
      0, 0, 0 },

    { rap_string("request_completion"), NULL,
      rap_http_variable_request_completion,
      0, 0, 0 },

    { rap_string("request_body"), NULL,
      rap_http_variable_request_body,
      0, 0, 0 },

    { rap_string("request_body_file"), NULL,
      rap_http_variable_request_body_file,
      0, 0, 0 },

    { rap_string("request_length"), NULL, rap_http_variable_request_length,
      0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("request_time"), NULL, rap_http_variable_request_time,
      0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("request_id"), NULL,
      rap_http_variable_request_id,
      0, 0, 0 },

    { rap_string("status"), NULL,
      rap_http_variable_status, 0,
      RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("sent_http_content_type"), NULL,
      rap_http_variable_sent_content_type, 0, 0, 0 },

    { rap_string("sent_http_content_length"), NULL,
      rap_http_variable_sent_content_length, 0, 0, 0 },

    { rap_string("sent_http_location"), NULL,
      rap_http_variable_sent_location, 0, 0, 0 },

    { rap_string("sent_http_last_modified"), NULL,
      rap_http_variable_sent_last_modified, 0, 0, 0 },

    { rap_string("sent_http_connection"), NULL,
      rap_http_variable_sent_connection, 0, 0, 0 },

    { rap_string("sent_http_keep_alive"), NULL,
      rap_http_variable_sent_keep_alive, 0, 0, 0 },

    { rap_string("sent_http_transfer_encoding"), NULL,
      rap_http_variable_sent_transfer_encoding, 0, 0, 0 },

    { rap_string("sent_http_cache_control"), NULL, rap_http_variable_headers,
      offsetof(rap_http_request_t, headers_out.cache_control), 0, 0 },

    { rap_string("sent_http_link"), NULL, rap_http_variable_headers,
      offsetof(rap_http_request_t, headers_out.link), 0, 0 },

    { rap_string("limit_rate"), rap_http_variable_set_limit_rate,
      rap_http_variable_request_get_size,
      offsetof(rap_http_request_t, limit_rate),
      RAP_HTTP_VAR_CHANGEABLE|RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("connection"), NULL,
      rap_http_variable_connection, 0, 0, 0 },

    { rap_string("connection_requests"), NULL,
      rap_http_variable_connection_requests, 0, 0, 0 },

    { rap_string("rap_version"), NULL, rap_http_variable_rap_version,
      0, 0, 0 },

    { rap_string("hostname"), NULL, rap_http_variable_hostname,
      0, 0, 0 },

    { rap_string("pid"), NULL, rap_http_variable_pid,
      0, 0, 0 },

    { rap_string("msec"), NULL, rap_http_variable_msec,
      0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("time_iso8601"), NULL, rap_http_variable_time_iso8601,
      0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("time_local"), NULL, rap_http_variable_time_local,
      0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

#if (RAP_HAVE_TCP_INFO)
    { rap_string("tcpinfo_rtt"), NULL, rap_http_variable_tcpinfo,
      0, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("tcpinfo_rttvar"), NULL, rap_http_variable_tcpinfo,
      1, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("tcpinfo_snd_cwnd"), NULL, rap_http_variable_tcpinfo,
      2, RAP_HTTP_VAR_NOCACHEABLE, 0 },

    { rap_string("tcpinfo_rcv_space"), NULL, rap_http_variable_tcpinfo,
      3, RAP_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { rap_string("http_"), NULL, rap_http_variable_unknown_header_in,
      0, RAP_HTTP_VAR_PREFIX, 0 },

    { rap_string("sent_http_"), NULL, rap_http_variable_unknown_header_out,
      0, RAP_HTTP_VAR_PREFIX, 0 },

    { rap_string("sent_trailer_"), NULL, rap_http_variable_unknown_trailer_out,
      0, RAP_HTTP_VAR_PREFIX, 0 },

    { rap_string("cookie_"), NULL, rap_http_variable_cookie,
      0, RAP_HTTP_VAR_PREFIX, 0 },

    { rap_string("arg_"), NULL, rap_http_variable_argument,
      0, RAP_HTTP_VAR_NOCACHEABLE|RAP_HTTP_VAR_PREFIX, 0 },

      rap_http_null_variable
};


rap_http_variable_value_t  rap_http_variable_null_value =
    rap_http_variable("");
rap_http_variable_value_t  rap_http_variable_true_value =
    rap_http_variable("1");


static rap_uint_t  rap_http_variable_depth = 100;


rap_http_variable_t *
rap_http_add_variable(rap_conf_t *cf, rap_str_t *name, rap_uint_t flags)
{
    rap_int_t                   rc;
    rap_uint_t                  i;
    rap_hash_key_t             *key;
    rap_http_variable_t        *v;
    rap_http_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    if (flags & RAP_HTTP_VAR_PREFIX) {
        return rap_http_add_prefix_variable(cf, name, flags);
    }

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || rap_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & RAP_HTTP_VAR_CHANGEABLE)) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & RAP_HTTP_VAR_WEAK)) {
            v->flags &= ~RAP_HTTP_VAR_WEAK;
        }

        return v;
    }

    v = rap_palloc(cf->pool, sizeof(rap_http_variable_t));
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


static rap_http_variable_t *
rap_http_add_prefix_variable(rap_conf_t *cf, rap_str_t *name, rap_uint_t flags)
{
    rap_uint_t                  i;
    rap_http_variable_t        *v;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    v = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || rap_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        v = &v[i];

        if (!(v->flags & RAP_HTTP_VAR_CHANGEABLE)) {
            rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & RAP_HTTP_VAR_WEAK)) {
            v->flags &= ~RAP_HTTP_VAR_WEAK;
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
rap_http_get_variable_index(rap_conf_t *cf, rap_str_t *name)
{
    rap_uint_t                  i;
    rap_http_variable_t        *v;
    rap_http_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return RAP_ERROR;
    }

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (rap_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(rap_http_variable_t))
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


rap_http_variable_value_t *
rap_http_get_indexed_variable(rap_http_request_t *r, rap_uint_t index)
{
    rap_http_variable_t        *v;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    if (cmcf->variables.nelts <= index) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (r->variables[index].not_found || r->variables[index].valid) {
        return &r->variables[index];
    }

    v = cmcf->variables.elts;

    if (rap_http_variable_depth == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    rap_http_variable_depth--;

    if (v[index].get_handler(r, &r->variables[index], v[index].data)
        == RAP_OK)
    {
        rap_http_variable_depth++;

        if (v[index].flags & RAP_HTTP_VAR_NOCACHEABLE) {
            r->variables[index].no_cacheable = 1;
        }

        return &r->variables[index];
    }

    rap_http_variable_depth++;

    r->variables[index].valid = 0;
    r->variables[index].not_found = 1;

    return NULL;
}


rap_http_variable_value_t *
rap_http_get_flushed_variable(rap_http_request_t *r, rap_uint_t index)
{
    rap_http_variable_value_t  *v;

    v = &r->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return rap_http_get_indexed_variable(r, index);
}


rap_http_variable_value_t *
rap_http_get_variable(rap_http_request_t *r, rap_str_t *name, rap_uint_t key)
{
    size_t                      len;
    rap_uint_t                  i, n;
    rap_http_variable_t        *v;
    rap_http_variable_value_t  *vv;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    v = rap_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & RAP_HTTP_VAR_INDEXED) {
            return rap_http_get_flushed_variable(r, v->index);
        }

        if (rap_http_variable_depth == 0) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        rap_http_variable_depth--;

        vv = rap_palloc(r->pool, sizeof(rap_http_variable_value_t));

        if (vv && v->get_handler(r, vv, v->data) == RAP_OK) {
            rap_http_variable_depth++;
            return vv;
        }

        rap_http_variable_depth++;
        return NULL;
    }

    vv = rap_palloc(r->pool, sizeof(rap_http_variable_value_t));
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
        if (v[n].get_handler(r, vv, (uintptr_t) name) == RAP_OK) {
            return vv;
        }

        return NULL;
    }

    vv->not_found = 1;

    return vv;
}


static rap_int_t
rap_http_variable_request(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    rap_str_t  *s;

    s = (rap_str_t *) ((char *) r + data);

    if (s->data) {
        v->len = s->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->data;

    } else {
        v->not_found = 1;
    }

    return RAP_OK;
}


#if 0

static void
rap_http_variable_request_set(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_str_t  *s;

    s = (rap_str_t *) ((char *) r + data);

    s->len = v->len;
    s->data = v->data;
}

#endif


static rap_int_t
rap_http_variable_request_get_size(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    size_t  *sp;

    sp = (size_t *) ((char *) r + data);

    v->data = rap_pnalloc(r->pool, RAP_SIZE_T_LEN);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(v->data, "%uz", *sp) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_header(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    rap_table_elt_t  *h;

    h = *(rap_table_elt_t **) ((char *) r + data);

    if (h) {
        v->len = h->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = h->value.data;

    } else {
        v->not_found = 1;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_variable_cookies(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    return rap_http_variable_headers_internal(r, v, data, ';');
}


static rap_int_t
rap_http_variable_headers(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    return rap_http_variable_headers_internal(r, v, data, ',');
}


static rap_int_t
rap_http_variable_headers_internal(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data, u_char sep)
{
    size_t             len;
    u_char            *p, *end;
    rap_uint_t         i, n;
    rap_array_t       *a;
    rap_table_elt_t  **h;

    a = (rap_array_t *) ((char *) r + data);

    n = a->nelts;
    h = a->elts;

    len = 0;

    for (i = 0; i < n; i++) {

        if (h[i]->hash == 0) {
            continue;
        }

        len += h[i]->value.len + 2;
    }

    if (len == 0) {
        v->not_found = 1;
        return RAP_OK;
    }

    len -= 2;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (n == 1) {
        v->len = (*h)->value.len;
        v->data = (*h)->value.data;

        return RAP_OK;
    }

    p = rap_pnalloc(r->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = len;
    v->data = p;

    end = p + len;

    for (i = 0; /* void */ ; i++) {

        if (h[i]->hash == 0) {
            continue;
        }

        p = rap_copy(p, h[i]->value.data, h[i]->value.len);

        if (p == end) {
            break;
        }

        *p++ = sep; *p++ = ' ';
    }

    return RAP_OK;
}


static rap_int_t
rap_http_variable_unknown_header_in(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    return rap_http_variable_unknown_header(v, (rap_str_t *) data,
                                            &r->headers_in.headers.part,
                                            sizeof("http_") - 1);
}


static rap_int_t
rap_http_variable_unknown_header_out(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    return rap_http_variable_unknown_header(v, (rap_str_t *) data,
                                            &r->headers_out.headers.part,
                                            sizeof("sent_http_") - 1);
}


static rap_int_t
rap_http_variable_unknown_trailer_out(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    return rap_http_variable_unknown_header(v, (rap_str_t *) data,
                                            &r->headers_out.trailers.part,
                                            sizeof("sent_trailer_") - 1);
}


rap_int_t
rap_http_variable_unknown_header(rap_http_variable_value_t *v, rap_str_t *var,
    rap_list_part_t *part, size_t prefix)
{
    u_char            ch;
    rap_uint_t        i, n;
    rap_table_elt_t  *header;

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        for (n = 0; n + prefix < var->len && n < header[i].key.len; n++) {
            ch = header[i].key.data[n];

            if (ch >= 'A' && ch <= 'Z') {
                ch |= 0x20;

            } else if (ch == '-') {
                ch = '_';
            }

            if (var->data[n + prefix] != ch) {
                break;
            }
        }

        if (n + prefix == var->len && n == header[i].key.len) {
            v->len = header[i].value.len;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = header[i].value.data;

            return RAP_OK;
        }
    }

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_request_line(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p, *s;

    s = r->request_line.data;

    if (s == NULL) {
        s = r->request_start;

        if (s == NULL) {
            v->not_found = 1;
            return RAP_OK;
        }

        for (p = s; p < r->header_in->last; p++) {
            if (*p == CR || *p == LF) {
                break;
            }
        }

        r->request_line.len = p - s;
        r->request_line.data = s;
    }

    v->len = r->request_line.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_cookie(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    rap_str_t *name = (rap_str_t *) data;

    rap_str_t  cookie, s;

    s.len = name->len - (sizeof("cookie_") - 1);
    s.data = name->data + sizeof("cookie_") - 1;

    if (rap_http_parse_multi_header_lines(&r->headers_in.cookies, &s, &cookie)
        == RAP_DECLINED)
    {
        v->not_found = 1;
        return RAP_OK;
    }

    v->len = cookie.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cookie.data;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_argument(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    rap_str_t *name = (rap_str_t *) data;

    u_char     *arg;
    size_t      len;
    rap_str_t   value;

    len = name->len - (sizeof("arg_") - 1);
    arg = name->data + sizeof("arg_") - 1;

    if (rap_http_arg(r, arg, len, &value) != RAP_OK) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->data = value.data;
    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;
}


#if (RAP_HAVE_TCP_INFO)

static rap_int_t
rap_http_variable_tcpinfo(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    struct tcp_info  ti;
    socklen_t        len;
    uint32_t         value;

    len = sizeof(struct tcp_info);
    if (getsockopt(r->connection->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == -1) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->data = rap_pnalloc(r->pool, RAP_INT32_LEN);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    switch (data) {
    case 0:
        value = ti.tcpi_rtt;
        break;

    case 1:
        value = ti.tcpi_rttvar;
        break;

    case 2:
        value = ti.tcpi_snd_cwnd;
        break;

    case 3:
        value = ti.tcpi_rcv_space;
        break;

    /* suppress warning */
    default:
        value = 0;
        break;
    }

    v->len = rap_sprintf(v->data, "%uD", value) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;
}

#endif


static rap_int_t
rap_http_variable_content_length(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_in.content_length) {
        v->len = r->headers_in.content_length->value.len;
        v->data = r->headers_in.content_length->value.data;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

    } else if (r->reading_body) {
        v->not_found = 1;
        v->no_cacheable = 1;

    } else if (r->headers_in.content_length_n >= 0) {
        p = rap_pnalloc(r->pool, RAP_OFF_T_LEN);
        if (p == NULL) {
            return RAP_ERROR;
        }

        v->len = rap_sprintf(p, "%O", r->headers_in.content_length_n) - p;
        v->data = p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

    } else {
        v->not_found = 1;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_variable_host(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    rap_http_core_srv_conf_t  *cscf;

    if (r->headers_in.server.len) {
        v->len = r->headers_in.server.len;
        v->data = r->headers_in.server.data;

    } else {
        cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

        v->len = cscf->server_name.len;
        v->data = cscf->server_name.data;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_binary_remote_addr(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    struct sockaddr_in   *sin;
#if (RAP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (r->connection->sockaddr->sa_family) {

#if (RAP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;

        v->len = sizeof(struct in6_addr);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = sin6->sin6_addr.s6_addr;

        break;
#endif

#if (RAP_HAVE_UNIX_DOMAIN)
    case AF_UNIX:

        v->len = r->connection->addr_text.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->connection->addr_text.data;

        break;
#endif

    default: /* AF_INET */
        sin = (struct sockaddr_in *) r->connection->sockaddr;

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
rap_http_variable_remote_addr(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    v->len = r->connection->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->connection->addr_text.data;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_remote_port(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rap_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    port = rap_inet_get_port(r->connection->sockaddr);

    if (port > 0 && port < 65536) {
        v->len = rap_sprintf(v->data, "%ui", port) - v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_variable_proxy_protocol_addr(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_str_t             *addr;
    rap_proxy_protocol_t  *pp;

    pp = r->connection->proxy_protocol;
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
rap_http_variable_proxy_protocol_port(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_uint_t             port;
    rap_proxy_protocol_t  *pp;

    pp = r->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return RAP_OK;
    }

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rap_pnalloc(r->pool, sizeof("65535") - 1);
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
rap_http_variable_server_addr(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_str_t  s;
    u_char     addr[RAP_SOCKADDR_STRLEN];

    s.len = RAP_SOCKADDR_STRLEN;
    s.data = addr;

    if (rap_connection_local_sockaddr(r->connection, &s, 0) != RAP_OK) {
        return RAP_ERROR;
    }

    s.data = rap_pnalloc(r->pool, s.len);
    if (s.data == NULL) {
        return RAP_ERROR;
    }

    rap_memcpy(s.data, addr, s.len);

    v->len = s.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s.data;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_server_port(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (rap_connection_local_sockaddr(r->connection, NULL, 0) != RAP_OK) {
        return RAP_ERROR;
    }

    v->data = rap_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    port = rap_inet_get_port(r->connection->local_sockaddr);

    if (port > 0 && port < 65536) {
        v->len = rap_sprintf(v->data, "%ui", port) - v->data;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_variable_scheme(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
#if (RAP_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("https") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "https";

        return RAP_OK;
    }

#endif

    v->len = sizeof("http") - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "http";

    return RAP_OK;
}


static rap_int_t
rap_http_variable_https(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
#if (RAP_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("on") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "on";

        return RAP_OK;
    }

#endif

    *v = rap_http_variable_null_value;

    return RAP_OK;
}


static void
rap_http_variable_set_args(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    r->args.len = v->len;
    r->args.data = v->data;
    r->valid_unparsed_uri = 0;
}


static rap_int_t
rap_http_variable_is_args(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->args.len == 0) {
        *v = rap_http_variable_null_value;
        return RAP_OK;
    }

    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "?";

    return RAP_OK;
}


static rap_int_t
rap_http_variable_document_root(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_str_t                  path;
    rap_http_core_loc_conf_t  *clcf;

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (clcf->root_lengths == NULL) {
        v->len = clcf->root.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = clcf->root.data;

    } else {
        if (rap_http_script_run(r, &path, clcf->root_lengths->elts, 0,
                                clcf->root_values->elts)
            == NULL)
        {
            return RAP_ERROR;
        }

        if (rap_get_full_name(r->pool, (rap_str_t *) &rap_cycle->prefix, &path)
            != RAP_OK)
        {
            return RAP_ERROR;
        }

        v->len = path.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = path.data;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_variable_realpath_root(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *real;
    size_t                     len;
    rap_str_t                  path;
    rap_http_core_loc_conf_t  *clcf;
#if (RAP_HAVE_MAX_PATH)
    u_char                     buffer[RAP_MAX_PATH];
#endif

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (clcf->root_lengths == NULL) {
        path = clcf->root;

    } else {
        if (rap_http_script_run(r, &path, clcf->root_lengths->elts, 1,
                                clcf->root_values->elts)
            == NULL)
        {
            return RAP_ERROR;
        }

        path.data[path.len - 1] = '\0';

        if (rap_get_full_name(r->pool, (rap_str_t *) &rap_cycle->prefix, &path)
            != RAP_OK)
        {
            return RAP_ERROR;
        }
    }

#if (RAP_HAVE_MAX_PATH)
    real = buffer;
#else
    real = NULL;
#endif

    real = rap_realpath(path.data, real);

    if (real == NULL) {
        rap_log_error(RAP_LOG_CRIT, r->connection->log, rap_errno,
                      rap_realpath_n " \"%s\" failed", path.data);
        return RAP_ERROR;
    }

    len = rap_strlen(real);

    v->data = rap_pnalloc(r->pool, len);
    if (v->data == NULL) {
#if !(RAP_HAVE_MAX_PATH)
        rap_free(real);
#endif
        return RAP_ERROR;
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    rap_memcpy(v->data, real, len);

#if !(RAP_HAVE_MAX_PATH)
    rap_free(real);
#endif

    return RAP_OK;
}


static rap_int_t
rap_http_variable_request_filename(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    size_t     root;
    rap_str_t  path;

    if (rap_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return RAP_ERROR;
    }

    /* rap_http_map_uri_to_path() allocates memory for terminating '\0' */

    v->len = path.len - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = path.data;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_server_name(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_http_core_srv_conf_t  *cscf;

    cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);

    v->len = cscf->server_name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cscf->server_name.data;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_request_method(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->main->method_name.data) {
        v->len = r->main->method_name.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->main->method_name.data;

    } else {
        v->not_found = 1;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_variable_remote_user(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_int_t  rc;

    rc = rap_http_auth_basic_user(r);

    if (rc == RAP_DECLINED) {
        v->not_found = 1;
        return RAP_OK;
    }

    if (rc == RAP_ERROR) {
        return RAP_ERROR;
    }

    v->len = r->headers_in.user.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->headers_in.user.data;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_bytes_sent(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(r->pool, RAP_OFF_T_LEN);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(p, "%O", r->connection->sent) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_body_bytes_sent(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    off_t    sent;
    u_char  *p;

    sent = r->connection->sent - r->header_size;

    if (sent < 0) {
        sent = 0;
    }

    p = rap_pnalloc(r->pool, RAP_OFF_T_LEN);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(p, "%O", sent) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_pipe(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    v->data = (u_char *) (r->pipeline ? "p" : ".");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_status(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_uint_t  status;

    v->data = rap_pnalloc(r->pool, RAP_INT_T_LEN);
    if (v->data == NULL) {
        return RAP_ERROR;
    }

    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == RAP_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }

    v->len = rap_sprintf(v->data, "%03ui", status) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_sent_content_type(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->headers_out.content_type.len) {
        v->len = r->headers_out.content_type.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.content_type.data;

    } else {
        v->not_found = 1;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_variable_sent_content_length(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_out.content_length) {
        v->len = r->headers_out.content_length->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.content_length->value.data;

        return RAP_OK;
    }

    if (r->headers_out.content_length_n >= 0) {
        p = rap_pnalloc(r->pool, RAP_OFF_T_LEN);
        if (p == NULL) {
            return RAP_ERROR;
        }

        v->len = rap_sprintf(p, "%O", r->headers_out.content_length_n) - p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = p;

        return RAP_OK;
    }

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_sent_location(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    rap_str_t  name;

    if (r->headers_out.location) {
        v->len = r->headers_out.location->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.location->value.data;

        return RAP_OK;
    }

    rap_str_set(&name, "sent_http_location");

    return rap_http_variable_unknown_header(v, &name,
                                            &r->headers_out.headers.part,
                                            sizeof("sent_http_") - 1);
}


static rap_int_t
rap_http_variable_sent_last_modified(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_out.last_modified) {
        v->len = r->headers_out.last_modified->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.last_modified->value.data;

        return RAP_OK;
    }

    if (r->headers_out.last_modified_time >= 0) {
        p = rap_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (p == NULL) {
            return RAP_ERROR;
        }

        v->len = rap_http_time(p, r->headers_out.last_modified_time) - p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = p;

        return RAP_OK;
    }

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_sent_connection(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    size_t   len;
    char    *p;

    if (r->headers_out.status == RAP_HTTP_SWITCHING_PROTOCOLS) {
        len = sizeof("upgrade") - 1;
        p = "upgrade";

    } else if (r->keepalive) {
        len = sizeof("keep-alive") - 1;
        p = "keep-alive";

    } else {
        len = sizeof("close") - 1;
        p = "close";
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) p;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_sent_keep_alive(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    rap_http_core_loc_conf_t  *clcf;

    if (r->keepalive) {
        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

        if (clcf->keepalive_header) {

            p = rap_pnalloc(r->pool, sizeof("timeout=") - 1 + RAP_TIME_T_LEN);
            if (p == NULL) {
                return RAP_ERROR;
            }

            v->len = rap_sprintf(p, "timeout=%T", clcf->keepalive_header) - p;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = p;

            return RAP_OK;
        }
    }

    v->not_found = 1;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_sent_transfer_encoding(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->chunked) {
        v->len = sizeof("chunked") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "chunked";

    } else {
        v->not_found = 1;
    }

    return RAP_OK;
}


static void
rap_http_variable_set_limit_rate(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    ssize_t    s;
    rap_str_t  val;

    val.len = v->len;
    val.data = v->data;

    s = rap_parse_size(&val);

    if (s == RAP_ERROR) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "invalid $limit_rate \"%V\"", &val);
        return;
    }

    r->limit_rate = s;
    r->limit_rate_set = 1;
}


static rap_int_t
rap_http_variable_request_completion(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->request_complete) {
        v->len = 2;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "OK";

        return RAP_OK;
    }

    *v = rap_http_variable_null_value;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_request_body(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char       *p;
    size_t        len;
    rap_buf_t    *buf;
    rap_chain_t  *cl;

    if (r->request_body == NULL
        || r->request_body->bufs == NULL
        || r->request_body->temp_file)
    {
        v->not_found = 1;

        return RAP_OK;
    }

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {
        v->len = buf->last - buf->pos;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = buf->pos;

        return RAP_OK;
    }

    len = buf->last - buf->pos;
    cl = cl->next;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    p = rap_pnalloc(r->pool, len);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->data = p;
    cl = r->request_body->bufs;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        p = rap_cpymem(p, buf->pos, buf->last - buf->pos);
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_request_body_file(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        v->not_found = 1;

        return RAP_OK;
    }

    v->len = r->request_body->temp_file->file.name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->request_body->temp_file->file.name.data;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_request_length(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(r->pool, RAP_OFF_T_LEN);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(p, "%O", r->request_length) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_request_time(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    rap_time_t      *tp;
    rap_msec_int_t   ms;

    p = rap_pnalloc(r->pool, RAP_TIME_T_LEN + 4);
    if (p == NULL) {
        return RAP_ERROR;
    }

    tp = rap_timeofday();

    ms = (rap_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = rap_max(ms, 0);

    v->len = rap_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_request_id(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *id;

#if (RAP_OPENSSL)
    u_char   random_bytes[16];
#endif

    id = rap_pnalloc(r->pool, 32);
    if (id == NULL) {
        return RAP_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = 32;
    v->data = id;

#if (RAP_OPENSSL)

    if (RAND_bytes(random_bytes, 16) == 1) {
        rap_hex_dump(id, random_bytes, 16);
        return RAP_OK;
    }

    rap_ssl_error(RAP_LOG_ERR, r->connection->log, 0, "RAND_bytes() failed");

#endif

    rap_sprintf(id, "%08xD%08xD%08xD%08xD",
                (uint32_t) rap_random(), (uint32_t) rap_random(),
                (uint32_t) rap_random(), (uint32_t) rap_random());

    return RAP_OK;
}


static rap_int_t
rap_http_variable_connection(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(r->pool, RAP_ATOMIC_T_LEN);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(p, "%uA", r->connection->number) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_connection_requests(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(r->pool, RAP_INT_T_LEN);
    if (p == NULL) {
        return RAP_ERROR;
    }

    v->len = rap_sprintf(p, "%ui", r->connection->requests) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_rap_version(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(RAP_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) RAP_VERSION;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_hostname(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    v->len = rap_cycle->hostname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = rap_cycle->hostname.data;

    return RAP_OK;
}


static rap_int_t
rap_http_variable_pid(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(r->pool, RAP_INT64_LEN);
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
rap_http_variable_msec(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    rap_time_t  *tp;

    p = rap_pnalloc(r->pool, RAP_TIME_T_LEN + 4);
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
rap_http_variable_time_iso8601(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(r->pool, rap_cached_http_log_iso8601.len);
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
rap_http_variable_time_local(rap_http_request_t *r,
    rap_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rap_pnalloc(r->pool, rap_cached_http_log_time.len);
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


void *
rap_http_map_find(rap_http_request_t *r, rap_http_map_t *map, rap_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    rap_uint_t   key;

    len = match->len;

    if (len) {
        low = rap_pnalloc(r->pool, len);
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
        rap_int_t              n;
        rap_uint_t             i;
        rap_http_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = rap_http_regex_exec(r, reg[i].regex, match);

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
rap_http_variable_not_found(rap_http_request_t *r, rap_http_variable_value_t *v,
    uintptr_t data)
{
    v->not_found = 1;
    return RAP_OK;
}


rap_http_regex_t *
rap_http_regex_compile(rap_conf_t *cf, rap_regex_compile_t *rc)
{
    u_char                     *p;
    size_t                      size;
    rap_str_t                   name;
    rap_uint_t                  i, n;
    rap_http_variable_t        *v;
    rap_http_regex_t           *re;
    rap_http_regex_variable_t  *rv;
    rap_http_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (rap_regex_compile(rc) != RAP_OK) {
        rap_conf_log_error(RAP_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = rap_pcalloc(cf->pool, sizeof(rap_http_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);
    cmcf->ncaptures = rap_max(cmcf->ncaptures, re->ncaptures);

    n = (rap_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = rap_palloc(rc->pool, n * sizeof(rap_http_regex_variable_t));
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

        v = rap_http_add_variable(cf, &name, RAP_HTTP_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = rap_http_get_variable_index(cf, &name);
        if (rv[i].index == RAP_ERROR) {
            return NULL;
        }

        v->get_handler = rap_http_variable_not_found;

        p += size;
    }

    return re;
}


rap_int_t
rap_http_regex_exec(rap_http_request_t *r, rap_http_regex_t *re, rap_str_t *s)
{
    rap_int_t                   rc, index;
    rap_uint_t                  i, n, len;
    rap_http_variable_value_t  *vv;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_get_module_main_conf(r, rap_http_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (r->captures == NULL || r->realloc_captures) {
            r->realloc_captures = 0;

            r->captures = rap_palloc(r->pool, len * sizeof(int));
            if (r->captures == NULL) {
                return RAP_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = rap_regex_exec(re->regex, s, r->captures, len);

    if (rc == RAP_REGEX_NO_MATCHED) {
        return RAP_DECLINED;
    }

    if (rc < 0) {
        rap_log_error(RAP_LOG_ALERT, r->connection->log, 0,
                      rap_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, s, &re->name);
        return RAP_ERROR;
    }

    for (i = 0; i < re->nvariables; i++) {

        n = re->variables[i].capture;
        index = re->variables[i].index;
        vv = &r->variables[index];

        vv->len = r->captures[n + 1] - r->captures[n];
        vv->valid = 1;
        vv->no_cacheable = 0;
        vv->not_found = 0;
        vv->data = &s->data[r->captures[n]];

#if (RAP_DEBUG)
        {
        rap_http_variable_t  *v;

        v = cmcf->variables.elts;

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    r->ncaptures = rc * 2;
    r->captures_data = s->data;

    return RAP_OK;
}

#endif


rap_int_t
rap_http_variables_add_core_vars(rap_conf_t *cf)
{
    rap_http_variable_t        *cv, *v;
    rap_http_core_main_conf_t  *cmcf;

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

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
                       sizeof(rap_http_variable_t))
        != RAP_OK)
    {
        return RAP_ERROR;
    }

    for (cv = rap_http_core_variables; cv->name.len; cv++) {
        v = rap_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return RAP_ERROR;
        }

        *v = *cv;
    }

    return RAP_OK;
}


rap_int_t
rap_http_variables_init_vars(rap_conf_t *cf)
{
    size_t                      len;
    rap_uint_t                  i, n;
    rap_hash_key_t             *key;
    rap_hash_init_t             hash;
    rap_http_variable_t        *v, *av, *pv;
    rap_http_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed http variables */

    cmcf = rap_http_conf_get_module_main_conf(cf, rap_http_core_module);

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

                av->flags |= RAP_HTTP_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                if (av->get_handler == NULL
                    || (av->flags & RAP_HTTP_VAR_WEAK))
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

        if (av->flags & RAP_HTTP_VAR_NOHASH) {
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
