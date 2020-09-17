
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>
#include <rap.h>


static rp_http_variable_t *rp_http_add_prefix_variable(rp_conf_t *cf,
    rp_str_t *name, rp_uint_t flags);

static rp_int_t rp_http_variable_request(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
#if 0
static void rp_http_variable_request_set(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
#endif
static rp_int_t rp_http_variable_request_get_size(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_header(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);

static rp_int_t rp_http_variable_cookies(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_headers(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_headers_internal(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data, u_char sep);

static rp_int_t rp_http_variable_unknown_header_in(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_unknown_header_out(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_unknown_trailer_out(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_request_line(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_cookie(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_argument(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
#if (RP_HAVE_TCP_INFO)
static rp_int_t rp_http_variable_tcpinfo(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
#endif

static rp_int_t rp_http_variable_content_length(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_host(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_binary_remote_addr(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_remote_addr(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_remote_port(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_proxy_protocol_addr(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_proxy_protocol_port(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_server_addr(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_server_port(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_scheme(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_https(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static void rp_http_variable_set_args(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_is_args(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_document_root(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_realpath_root(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_request_filename(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_server_name(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_request_method(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_remote_user(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_bytes_sent(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_body_bytes_sent(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_pipe(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_request_completion(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_request_body(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_request_body_file(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_request_length(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_request_time(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_request_id(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_status(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);

static rp_int_t rp_http_variable_sent_content_type(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_sent_content_length(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_sent_location(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_sent_last_modified(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_sent_connection(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_sent_keep_alive(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_sent_transfer_encoding(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static void rp_http_variable_set_limit_rate(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);

static rp_int_t rp_http_variable_connection(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_connection_requests(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);

static rp_int_t rp_http_variable_rap_version(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_hostname(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_pid(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_msec(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_time_iso8601(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);
static rp_int_t rp_http_variable_time_local(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data);

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
 * rp_http_variable_unknown_header_in(), but for performance reasons
 * they are handled using dedicated entries
 */

static rp_http_variable_t  rp_http_core_variables[] = {

    { rp_string("http_host"), NULL, rp_http_variable_header,
      offsetof(rp_http_request_t, headers_in.host), 0, 0 },

    { rp_string("http_user_agent"), NULL, rp_http_variable_header,
      offsetof(rp_http_request_t, headers_in.user_agent), 0, 0 },

    { rp_string("http_referer"), NULL, rp_http_variable_header,
      offsetof(rp_http_request_t, headers_in.referer), 0, 0 },

#if (RP_HTTP_GZIP)
    { rp_string("http_via"), NULL, rp_http_variable_header,
      offsetof(rp_http_request_t, headers_in.via), 0, 0 },
#endif

#if (RP_HTTP_X_FORWARDED_FOR)
    { rp_string("http_x_forwarded_for"), NULL, rp_http_variable_headers,
      offsetof(rp_http_request_t, headers_in.x_forwarded_for), 0, 0 },
#endif

    { rp_string("http_cookie"), NULL, rp_http_variable_cookies,
      offsetof(rp_http_request_t, headers_in.cookies), 0, 0 },

    { rp_string("content_length"), NULL, rp_http_variable_content_length,
      0, 0, 0 },

    { rp_string("content_type"), NULL, rp_http_variable_header,
      offsetof(rp_http_request_t, headers_in.content_type), 0, 0 },

    { rp_string("host"), NULL, rp_http_variable_host, 0, 0, 0 },

    { rp_string("binary_remote_addr"), NULL,
      rp_http_variable_binary_remote_addr, 0, 0, 0 },

    { rp_string("remote_addr"), NULL, rp_http_variable_remote_addr, 0, 0, 0 },

    { rp_string("remote_port"), NULL, rp_http_variable_remote_port, 0, 0, 0 },

    { rp_string("proxy_protocol_addr"), NULL,
      rp_http_variable_proxy_protocol_addr,
      offsetof(rp_proxy_protocol_t, src_addr), 0, 0 },

    { rp_string("proxy_protocol_port"), NULL,
      rp_http_variable_proxy_protocol_port,
      offsetof(rp_proxy_protocol_t, src_port), 0, 0 },

    { rp_string("proxy_protocol_server_addr"), NULL,
      rp_http_variable_proxy_protocol_addr,
      offsetof(rp_proxy_protocol_t, dst_addr), 0, 0 },

    { rp_string("proxy_protocol_server_port"), NULL,
      rp_http_variable_proxy_protocol_port,
      offsetof(rp_proxy_protocol_t, dst_port), 0, 0 },

    { rp_string("server_addr"), NULL, rp_http_variable_server_addr, 0, 0, 0 },

    { rp_string("server_port"), NULL, rp_http_variable_server_port, 0, 0, 0 },

    { rp_string("server_protocol"), NULL, rp_http_variable_request,
      offsetof(rp_http_request_t, http_protocol), 0, 0 },

    { rp_string("scheme"), NULL, rp_http_variable_scheme, 0, 0, 0 },

    { rp_string("https"), NULL, rp_http_variable_https, 0, 0, 0 },

    { rp_string("request_uri"), NULL, rp_http_variable_request,
      offsetof(rp_http_request_t, unparsed_uri), 0, 0 },

    { rp_string("uri"), NULL, rp_http_variable_request,
      offsetof(rp_http_request_t, uri),
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("document_uri"), NULL, rp_http_variable_request,
      offsetof(rp_http_request_t, uri),
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("request"), NULL, rp_http_variable_request_line, 0, 0, 0 },

    { rp_string("document_root"), NULL,
      rp_http_variable_document_root, 0, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("realpath_root"), NULL,
      rp_http_variable_realpath_root, 0, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("query_string"), NULL, rp_http_variable_request,
      offsetof(rp_http_request_t, args),
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("args"),
      rp_http_variable_set_args,
      rp_http_variable_request,
      offsetof(rp_http_request_t, args),
      RP_HTTP_VAR_CHANGEABLE|RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("is_args"), NULL, rp_http_variable_is_args,
      0, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("request_filename"), NULL,
      rp_http_variable_request_filename, 0,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("server_name"), NULL, rp_http_variable_server_name, 0, 0, 0 },

    { rp_string("request_method"), NULL,
      rp_http_variable_request_method, 0,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("remote_user"), NULL, rp_http_variable_remote_user, 0, 0, 0 },

    { rp_string("bytes_sent"), NULL, rp_http_variable_bytes_sent,
      0, 0, 0 },

    { rp_string("body_bytes_sent"), NULL, rp_http_variable_body_bytes_sent,
      0, 0, 0 },

    { rp_string("pipe"), NULL, rp_http_variable_pipe,
      0, 0, 0 },

    { rp_string("request_completion"), NULL,
      rp_http_variable_request_completion,
      0, 0, 0 },

    { rp_string("request_body"), NULL,
      rp_http_variable_request_body,
      0, 0, 0 },

    { rp_string("request_body_file"), NULL,
      rp_http_variable_request_body_file,
      0, 0, 0 },

    { rp_string("request_length"), NULL, rp_http_variable_request_length,
      0, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("request_time"), NULL, rp_http_variable_request_time,
      0, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("request_id"), NULL,
      rp_http_variable_request_id,
      0, 0, 0 },

    { rp_string("status"), NULL,
      rp_http_variable_status, 0,
      RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("sent_http_content_type"), NULL,
      rp_http_variable_sent_content_type, 0, 0, 0 },

    { rp_string("sent_http_content_length"), NULL,
      rp_http_variable_sent_content_length, 0, 0, 0 },

    { rp_string("sent_http_location"), NULL,
      rp_http_variable_sent_location, 0, 0, 0 },

    { rp_string("sent_http_last_modified"), NULL,
      rp_http_variable_sent_last_modified, 0, 0, 0 },

    { rp_string("sent_http_connection"), NULL,
      rp_http_variable_sent_connection, 0, 0, 0 },

    { rp_string("sent_http_keep_alive"), NULL,
      rp_http_variable_sent_keep_alive, 0, 0, 0 },

    { rp_string("sent_http_transfer_encoding"), NULL,
      rp_http_variable_sent_transfer_encoding, 0, 0, 0 },

    { rp_string("sent_http_cache_control"), NULL, rp_http_variable_headers,
      offsetof(rp_http_request_t, headers_out.cache_control), 0, 0 },

    { rp_string("sent_http_link"), NULL, rp_http_variable_headers,
      offsetof(rp_http_request_t, headers_out.link), 0, 0 },

    { rp_string("limit_rate"), rp_http_variable_set_limit_rate,
      rp_http_variable_request_get_size,
      offsetof(rp_http_request_t, limit_rate),
      RP_HTTP_VAR_CHANGEABLE|RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("connection"), NULL,
      rp_http_variable_connection, 0, 0, 0 },

    { rp_string("connection_requests"), NULL,
      rp_http_variable_connection_requests, 0, 0, 0 },

    { rp_string("rap_version"), NULL, rp_http_variable_rap_version,
      0, 0, 0 },

    { rp_string("hostname"), NULL, rp_http_variable_hostname,
      0, 0, 0 },

    { rp_string("pid"), NULL, rp_http_variable_pid,
      0, 0, 0 },

    { rp_string("msec"), NULL, rp_http_variable_msec,
      0, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("time_iso8601"), NULL, rp_http_variable_time_iso8601,
      0, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("time_local"), NULL, rp_http_variable_time_local,
      0, RP_HTTP_VAR_NOCACHEABLE, 0 },

#if (RP_HAVE_TCP_INFO)
    { rp_string("tcpinfo_rtt"), NULL, rp_http_variable_tcpinfo,
      0, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("tcpinfo_rttvar"), NULL, rp_http_variable_tcpinfo,
      1, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("tcpinfo_snd_cwnd"), NULL, rp_http_variable_tcpinfo,
      2, RP_HTTP_VAR_NOCACHEABLE, 0 },

    { rp_string("tcpinfo_rcv_space"), NULL, rp_http_variable_tcpinfo,
      3, RP_HTTP_VAR_NOCACHEABLE, 0 },
#endif

    { rp_string("http_"), NULL, rp_http_variable_unknown_header_in,
      0, RP_HTTP_VAR_PREFIX, 0 },

    { rp_string("sent_http_"), NULL, rp_http_variable_unknown_header_out,
      0, RP_HTTP_VAR_PREFIX, 0 },

    { rp_string("sent_trailer_"), NULL, rp_http_variable_unknown_trailer_out,
      0, RP_HTTP_VAR_PREFIX, 0 },

    { rp_string("cookie_"), NULL, rp_http_variable_cookie,
      0, RP_HTTP_VAR_PREFIX, 0 },

    { rp_string("arg_"), NULL, rp_http_variable_argument,
      0, RP_HTTP_VAR_NOCACHEABLE|RP_HTTP_VAR_PREFIX, 0 },

      rp_http_null_variable
};


rp_http_variable_value_t  rp_http_variable_null_value =
    rp_http_variable("");
rp_http_variable_value_t  rp_http_variable_true_value =
    rp_http_variable("1");


static rp_uint_t  rp_http_variable_depth = 100;


rp_http_variable_t *
rp_http_add_variable(rp_conf_t *cf, rp_str_t *name, rp_uint_t flags)
{
    rp_int_t                   rc;
    rp_uint_t                  i;
    rp_hash_key_t             *key;
    rp_http_variable_t        *v;
    rp_http_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return NULL;
    }

    if (flags & RP_HTTP_VAR_PREFIX) {
        return rp_http_add_prefix_variable(cf, name, flags);
    }

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    key = cmcf->variables_keys->keys.elts;
    for (i = 0; i < cmcf->variables_keys->keys.nelts; i++) {
        if (name->len != key[i].key.len
            || rp_strncasecmp(name->data, key[i].key.data, name->len) != 0)
        {
            continue;
        }

        v = key[i].value;

        if (!(v->flags & RP_HTTP_VAR_CHANGEABLE)) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & RP_HTTP_VAR_WEAK)) {
            v->flags &= ~RP_HTTP_VAR_WEAK;
        }

        return v;
    }

    v = rp_palloc(cf->pool, sizeof(rp_http_variable_t));
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


static rp_http_variable_t *
rp_http_add_prefix_variable(rp_conf_t *cf, rp_str_t *name, rp_uint_t flags)
{
    rp_uint_t                  i;
    rp_http_variable_t        *v;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    v = cmcf->prefix_variables.elts;
    for (i = 0; i < cmcf->prefix_variables.nelts; i++) {
        if (name->len != v[i].name.len
            || rp_strncasecmp(name->data, v[i].name.data, name->len) != 0)
        {
            continue;
        }

        v = &v[i];

        if (!(v->flags & RP_HTTP_VAR_CHANGEABLE)) {
            rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                               "the duplicate \"%V\" variable", name);
            return NULL;
        }

        if (!(flags & RP_HTTP_VAR_WEAK)) {
            v->flags &= ~RP_HTTP_VAR_WEAK;
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
rp_http_get_variable_index(rp_conf_t *cf, rp_str_t *name)
{
    rp_uint_t                  i;
    rp_http_variable_t        *v;
    rp_http_core_main_conf_t  *cmcf;

    if (name->len == 0) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0,
                           "invalid variable name \"$\"");
        return RP_ERROR;
    }

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

    v = cmcf->variables.elts;

    if (v == NULL) {
        if (rp_array_init(&cmcf->variables, cf->pool, 4,
                           sizeof(rp_http_variable_t))
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


rp_http_variable_value_t *
rp_http_get_indexed_variable(rp_http_request_t *r, rp_uint_t index)
{
    rp_http_variable_t        *v;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    if (cmcf->variables.nelts <= index) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      "unknown variable index: %ui", index);
        return NULL;
    }

    if (r->variables[index].not_found || r->variables[index].valid) {
        return &r->variables[index];
    }

    v = cmcf->variables.elts;

    if (rp_http_variable_depth == 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "cycle while evaluating variable \"%V\"",
                      &v[index].name);
        return NULL;
    }

    rp_http_variable_depth--;

    if (v[index].get_handler(r, &r->variables[index], v[index].data)
        == RP_OK)
    {
        rp_http_variable_depth++;

        if (v[index].flags & RP_HTTP_VAR_NOCACHEABLE) {
            r->variables[index].no_cacheable = 1;
        }

        return &r->variables[index];
    }

    rp_http_variable_depth++;

    r->variables[index].valid = 0;
    r->variables[index].not_found = 1;

    return NULL;
}


rp_http_variable_value_t *
rp_http_get_flushed_variable(rp_http_request_t *r, rp_uint_t index)
{
    rp_http_variable_value_t  *v;

    v = &r->variables[index];

    if (v->valid || v->not_found) {
        if (!v->no_cacheable) {
            return v;
        }

        v->valid = 0;
        v->not_found = 0;
    }

    return rp_http_get_indexed_variable(r, index);
}


rp_http_variable_value_t *
rp_http_get_variable(rp_http_request_t *r, rp_str_t *name, rp_uint_t key)
{
    size_t                      len;
    rp_uint_t                  i, n;
    rp_http_variable_t        *v;
    rp_http_variable_value_t  *vv;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    v = rp_hash_find(&cmcf->variables_hash, key, name->data, name->len);

    if (v) {
        if (v->flags & RP_HTTP_VAR_INDEXED) {
            return rp_http_get_flushed_variable(r, v->index);
        }

        if (rp_http_variable_depth == 0) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "cycle while evaluating variable \"%V\"", name);
            return NULL;
        }

        rp_http_variable_depth--;

        vv = rp_palloc(r->pool, sizeof(rp_http_variable_value_t));

        if (vv && v->get_handler(r, vv, v->data) == RP_OK) {
            rp_http_variable_depth++;
            return vv;
        }

        rp_http_variable_depth++;
        return NULL;
    }

    vv = rp_palloc(r->pool, sizeof(rp_http_variable_value_t));
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
        if (v[n].get_handler(r, vv, (uintptr_t) name) == RP_OK) {
            return vv;
        }

        return NULL;
    }

    vv->not_found = 1;

    return vv;
}


static rp_int_t
rp_http_variable_request(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    rp_str_t  *s;

    s = (rp_str_t *) ((char *) r + data);

    if (s->data) {
        v->len = s->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = s->data;

    } else {
        v->not_found = 1;
    }

    return RP_OK;
}


#if 0

static void
rp_http_variable_request_set(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_str_t  *s;

    s = (rp_str_t *) ((char *) r + data);

    s->len = v->len;
    s->data = v->data;
}

#endif


static rp_int_t
rp_http_variable_request_get_size(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    size_t  *sp;

    sp = (size_t *) ((char *) r + data);

    v->data = rp_pnalloc(r->pool, RP_SIZE_T_LEN);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    v->len = rp_sprintf(v->data, "%uz", *sp) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RP_OK;
}


static rp_int_t
rp_http_variable_header(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    rp_table_elt_t  *h;

    h = *(rp_table_elt_t **) ((char *) r + data);

    if (h) {
        v->len = h->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = h->value.data;

    } else {
        v->not_found = 1;
    }

    return RP_OK;
}


static rp_int_t
rp_http_variable_cookies(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    return rp_http_variable_headers_internal(r, v, data, ';');
}


static rp_int_t
rp_http_variable_headers(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    return rp_http_variable_headers_internal(r, v, data, ',');
}


static rp_int_t
rp_http_variable_headers_internal(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data, u_char sep)
{
    size_t             len;
    u_char            *p, *end;
    rp_uint_t         i, n;
    rp_array_t       *a;
    rp_table_elt_t  **h;

    a = (rp_array_t *) ((char *) r + data);

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
        return RP_OK;
    }

    len -= 2;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (n == 1) {
        v->len = (*h)->value.len;
        v->data = (*h)->value.data;

        return RP_OK;
    }

    p = rp_pnalloc(r->pool, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->len = len;
    v->data = p;

    end = p + len;

    for (i = 0; /* void */ ; i++) {

        if (h[i]->hash == 0) {
            continue;
        }

        p = rp_copy(p, h[i]->value.data, h[i]->value.len);

        if (p == end) {
            break;
        }

        *p++ = sep; *p++ = ' ';
    }

    return RP_OK;
}


static rp_int_t
rp_http_variable_unknown_header_in(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    return rp_http_variable_unknown_header(v, (rp_str_t *) data,
                                            &r->headers_in.headers.part,
                                            sizeof("http_") - 1);
}


static rp_int_t
rp_http_variable_unknown_header_out(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    return rp_http_variable_unknown_header(v, (rp_str_t *) data,
                                            &r->headers_out.headers.part,
                                            sizeof("sent_http_") - 1);
}


static rp_int_t
rp_http_variable_unknown_trailer_out(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    return rp_http_variable_unknown_header(v, (rp_str_t *) data,
                                            &r->headers_out.trailers.part,
                                            sizeof("sent_trailer_") - 1);
}


rp_int_t
rp_http_variable_unknown_header(rp_http_variable_value_t *v, rp_str_t *var,
    rp_list_part_t *part, size_t prefix)
{
    u_char            ch;
    rp_uint_t        i, n;
    rp_table_elt_t  *header;

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

            return RP_OK;
        }
    }

    v->not_found = 1;

    return RP_OK;
}


static rp_int_t
rp_http_variable_request_line(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p, *s;

    s = r->request_line.data;

    if (s == NULL) {
        s = r->request_start;

        if (s == NULL) {
            v->not_found = 1;
            return RP_OK;
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

    return RP_OK;
}


static rp_int_t
rp_http_variable_cookie(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    rp_str_t *name = (rp_str_t *) data;

    rp_str_t  cookie, s;

    s.len = name->len - (sizeof("cookie_") - 1);
    s.data = name->data + sizeof("cookie_") - 1;

    if (rp_http_parse_multi_header_lines(&r->headers_in.cookies, &s, &cookie)
        == RP_DECLINED)
    {
        v->not_found = 1;
        return RP_OK;
    }

    v->len = cookie.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cookie.data;

    return RP_OK;
}


static rp_int_t
rp_http_variable_argument(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    rp_str_t *name = (rp_str_t *) data;

    u_char     *arg;
    size_t      len;
    rp_str_t   value;

    len = name->len - (sizeof("arg_") - 1);
    arg = name->data + sizeof("arg_") - 1;

    if (rp_http_arg(r, arg, len, &value) != RP_OK) {
        v->not_found = 1;
        return RP_OK;
    }

    v->data = value.data;
    v->len = value.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RP_OK;
}


#if (RP_HAVE_TCP_INFO)

static rp_int_t
rp_http_variable_tcpinfo(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    struct tcp_info  ti;
    socklen_t        len;
    uint32_t         value;

    len = sizeof(struct tcp_info);
    if (getsockopt(r->connection->fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == -1) {
        v->not_found = 1;
        return RP_OK;
    }

    v->data = rp_pnalloc(r->pool, RP_INT32_LEN);
    if (v->data == NULL) {
        return RP_ERROR;
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

    v->len = rp_sprintf(v->data, "%uD", value) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RP_OK;
}

#endif


static rp_int_t
rp_http_variable_content_length(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
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
        p = rp_pnalloc(r->pool, RP_OFF_T_LEN);
        if (p == NULL) {
            return RP_ERROR;
        }

        v->len = rp_sprintf(p, "%O", r->headers_in.content_length_n) - p;
        v->data = p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

    } else {
        v->not_found = 1;
    }

    return RP_OK;
}


static rp_int_t
rp_http_variable_host(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    rp_http_core_srv_conf_t  *cscf;

    if (r->headers_in.server.len) {
        v->len = r->headers_in.server.len;
        v->data = r->headers_in.server.data;

    } else {
        cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

        v->len = cscf->server_name.len;
        v->data = cscf->server_name.data;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RP_OK;
}


static rp_int_t
rp_http_variable_binary_remote_addr(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    struct sockaddr_in   *sin;
#if (RP_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    switch (r->connection->sockaddr->sa_family) {

#if (RP_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->sockaddr;

        v->len = sizeof(struct in6_addr);
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = sin6->sin6_addr.s6_addr;

        break;
#endif

#if (RP_HAVE_UNIX_DOMAIN)
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

    return RP_OK;
}


static rp_int_t
rp_http_variable_remote_addr(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    v->len = r->connection->addr_text.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->connection->addr_text.data;

    return RP_OK;
}


static rp_int_t
rp_http_variable_remote_port(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rp_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    port = rp_inet_get_port(r->connection->sockaddr);

    if (port > 0 && port < 65536) {
        v->len = rp_sprintf(v->data, "%ui", port) - v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_http_variable_proxy_protocol_addr(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_str_t             *addr;
    rp_proxy_protocol_t  *pp;

    pp = r->connection->proxy_protocol;
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
rp_http_variable_proxy_protocol_port(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_uint_t             port;
    rp_proxy_protocol_t  *pp;

    pp = r->connection->proxy_protocol;
    if (pp == NULL) {
        v->not_found = 1;
        return RP_OK;
    }

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->data = rp_pnalloc(r->pool, sizeof("65535") - 1);
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
rp_http_variable_server_addr(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_str_t  s;
    u_char     addr[RP_SOCKADDR_STRLEN];

    s.len = RP_SOCKADDR_STRLEN;
    s.data = addr;

    if (rp_connection_local_sockaddr(r->connection, &s, 0) != RP_OK) {
        return RP_ERROR;
    }

    s.data = rp_pnalloc(r->pool, s.len);
    if (s.data == NULL) {
        return RP_ERROR;
    }

    rp_memcpy(s.data, addr, s.len);

    v->len = s.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = s.data;

    return RP_OK;
}


static rp_int_t
rp_http_variable_server_port(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_uint_t  port;

    v->len = 0;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (rp_connection_local_sockaddr(r->connection, NULL, 0) != RP_OK) {
        return RP_ERROR;
    }

    v->data = rp_pnalloc(r->pool, sizeof("65535") - 1);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    port = rp_inet_get_port(r->connection->local_sockaddr);

    if (port > 0 && port < 65536) {
        v->len = rp_sprintf(v->data, "%ui", port) - v->data;
    }

    return RP_OK;
}


static rp_int_t
rp_http_variable_scheme(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
#if (RP_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("https") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "https";

        return RP_OK;
    }

#endif

    v->len = sizeof("http") - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "http";

    return RP_OK;
}


static rp_int_t
rp_http_variable_https(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
#if (RP_HTTP_SSL)

    if (r->connection->ssl) {
        v->len = sizeof("on") - 1;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "on";

        return RP_OK;
    }

#endif

    *v = rp_http_variable_null_value;

    return RP_OK;
}


static void
rp_http_variable_set_args(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    r->args.len = v->len;
    r->args.data = v->data;
    r->valid_unparsed_uri = 0;
}


static rp_int_t
rp_http_variable_is_args(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    if (r->args.len == 0) {
        *v = rp_http_variable_null_value;
        return RP_OK;
    }

    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) "?";

    return RP_OK;
}


static rp_int_t
rp_http_variable_document_root(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_str_t                  path;
    rp_http_core_loc_conf_t  *clcf;

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->root_lengths == NULL) {
        v->len = clcf->root.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = clcf->root.data;

    } else {
        if (rp_http_script_run(r, &path, clcf->root_lengths->elts, 0,
                                clcf->root_values->elts)
            == NULL)
        {
            return RP_ERROR;
        }

        if (rp_get_full_name(r->pool, (rp_str_t *) &rp_cycle->prefix, &path)
            != RP_OK)
        {
            return RP_ERROR;
        }

        v->len = path.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = path.data;
    }

    return RP_OK;
}


static rp_int_t
rp_http_variable_realpath_root(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *real;
    size_t                     len;
    rp_str_t                  path;
    rp_http_core_loc_conf_t  *clcf;
#if (RP_HAVE_MAX_PATH)
    u_char                     buffer[RP_MAX_PATH];
#endif

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    if (clcf->root_lengths == NULL) {
        path = clcf->root;

    } else {
        if (rp_http_script_run(r, &path, clcf->root_lengths->elts, 1,
                                clcf->root_values->elts)
            == NULL)
        {
            return RP_ERROR;
        }

        path.data[path.len - 1] = '\0';

        if (rp_get_full_name(r->pool, (rp_str_t *) &rp_cycle->prefix, &path)
            != RP_OK)
        {
            return RP_ERROR;
        }
    }

#if (RP_HAVE_MAX_PATH)
    real = buffer;
#else
    real = NULL;
#endif

    real = rp_realpath(path.data, real);

    if (real == NULL) {
        rp_log_error(RP_LOG_CRIT, r->connection->log, rp_errno,
                      rp_realpath_n " \"%s\" failed", path.data);
        return RP_ERROR;
    }

    len = rp_strlen(real);

    v->data = rp_pnalloc(r->pool, len);
    if (v->data == NULL) {
#if !(RP_HAVE_MAX_PATH)
        rp_free(real);
#endif
        return RP_ERROR;
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    rp_memcpy(v->data, real, len);

#if !(RP_HAVE_MAX_PATH)
    rp_free(real);
#endif

    return RP_OK;
}


static rp_int_t
rp_http_variable_request_filename(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    size_t     root;
    rp_str_t  path;

    if (rp_http_map_uri_to_path(r, &path, &root, 0) == NULL) {
        return RP_ERROR;
    }

    /* rp_http_map_uri_to_path() allocates memory for terminating '\0' */

    v->len = path.len - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = path.data;

    return RP_OK;
}


static rp_int_t
rp_http_variable_server_name(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_http_core_srv_conf_t  *cscf;

    cscf = rp_http_get_module_srv_conf(r, rp_http_core_module);

    v->len = cscf->server_name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = cscf->server_name.data;

    return RP_OK;
}


static rp_int_t
rp_http_variable_request_method(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
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

    return RP_OK;
}


static rp_int_t
rp_http_variable_remote_user(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_int_t  rc;

    rc = rp_http_auth_basic_user(r);

    if (rc == RP_DECLINED) {
        v->not_found = 1;
        return RP_OK;
    }

    if (rc == RP_ERROR) {
        return RP_ERROR;
    }

    v->len = r->headers_in.user.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->headers_in.user.data;

    return RP_OK;
}


static rp_int_t
rp_http_variable_bytes_sent(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(r->pool, RP_OFF_T_LEN);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->len = rp_sprintf(p, "%O", r->connection->sent) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_http_variable_body_bytes_sent(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    off_t    sent;
    u_char  *p;

    sent = r->connection->sent - r->header_size;

    if (sent < 0) {
        sent = 0;
    }

    p = rp_pnalloc(r->pool, RP_OFF_T_LEN);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->len = rp_sprintf(p, "%O", sent) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_http_variable_pipe(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    v->data = (u_char *) (r->pipeline ? "p" : ".");
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RP_OK;
}


static rp_int_t
rp_http_variable_status(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_uint_t  status;

    v->data = rp_pnalloc(r->pool, RP_INT_T_LEN);
    if (v->data == NULL) {
        return RP_ERROR;
    }

    if (r->err_status) {
        status = r->err_status;

    } else if (r->headers_out.status) {
        status = r->headers_out.status;

    } else if (r->http_version == RP_HTTP_VERSION_9) {
        status = 9;

    } else {
        status = 0;
    }

    v->len = rp_sprintf(v->data, "%03ui", status) - v->data;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RP_OK;
}


static rp_int_t
rp_http_variable_sent_content_type(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
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

    return RP_OK;
}


static rp_int_t
rp_http_variable_sent_content_length(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_out.content_length) {
        v->len = r->headers_out.content_length->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.content_length->value.data;

        return RP_OK;
    }

    if (r->headers_out.content_length_n >= 0) {
        p = rp_pnalloc(r->pool, RP_OFF_T_LEN);
        if (p == NULL) {
            return RP_ERROR;
        }

        v->len = rp_sprintf(p, "%O", r->headers_out.content_length_n) - p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = p;

        return RP_OK;
    }

    v->not_found = 1;

    return RP_OK;
}


static rp_int_t
rp_http_variable_sent_location(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    rp_str_t  name;

    if (r->headers_out.location) {
        v->len = r->headers_out.location->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.location->value.data;

        return RP_OK;
    }

    rp_str_set(&name, "sent_http_location");

    return rp_http_variable_unknown_header(v, &name,
                                            &r->headers_out.headers.part,
                                            sizeof("sent_http_") - 1);
}


static rp_int_t
rp_http_variable_sent_last_modified(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    if (r->headers_out.last_modified) {
        v->len = r->headers_out.last_modified->value.len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = r->headers_out.last_modified->value.data;

        return RP_OK;
    }

    if (r->headers_out.last_modified_time >= 0) {
        p = rp_pnalloc(r->pool, sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1);
        if (p == NULL) {
            return RP_ERROR;
        }

        v->len = rp_http_time(p, r->headers_out.last_modified_time) - p;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = p;

        return RP_OK;
    }

    v->not_found = 1;

    return RP_OK;
}


static rp_int_t
rp_http_variable_sent_connection(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    size_t   len;
    char    *p;

    if (r->headers_out.status == RP_HTTP_SWITCHING_PROTOCOLS) {
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

    return RP_OK;
}


static rp_int_t
rp_http_variable_sent_keep_alive(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char                    *p;
    rp_http_core_loc_conf_t  *clcf;

    if (r->keepalive) {
        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

        if (clcf->keepalive_header) {

            p = rp_pnalloc(r->pool, sizeof("timeout=") - 1 + RP_TIME_T_LEN);
            if (p == NULL) {
                return RP_ERROR;
            }

            v->len = rp_sprintf(p, "timeout=%T", clcf->keepalive_header) - p;
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;
            v->data = p;

            return RP_OK;
        }
    }

    v->not_found = 1;

    return RP_OK;
}


static rp_int_t
rp_http_variable_sent_transfer_encoding(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
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

    return RP_OK;
}


static void
rp_http_variable_set_limit_rate(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    ssize_t    s;
    rp_str_t  val;

    val.len = v->len;
    val.data = v->data;

    s = rp_parse_size(&val);

    if (s == RP_ERROR) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "invalid $limit_rate \"%V\"", &val);
        return;
    }

    r->limit_rate = s;
    r->limit_rate_set = 1;
}


static rp_int_t
rp_http_variable_request_completion(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    if (r->request_complete) {
        v->len = 2;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = (u_char *) "OK";

        return RP_OK;
    }

    *v = rp_http_variable_null_value;

    return RP_OK;
}


static rp_int_t
rp_http_variable_request_body(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char       *p;
    size_t        len;
    rp_buf_t    *buf;
    rp_chain_t  *cl;

    if (r->request_body == NULL
        || r->request_body->bufs == NULL
        || r->request_body->temp_file)
    {
        v->not_found = 1;

        return RP_OK;
    }

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {
        v->len = buf->last - buf->pos;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
        v->data = buf->pos;

        return RP_OK;
    }

    len = buf->last - buf->pos;
    cl = cl->next;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    p = rp_pnalloc(r->pool, len);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->data = p;
    cl = r->request_body->bufs;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        p = rp_cpymem(p, buf->pos, buf->last - buf->pos);
    }

    v->len = len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return RP_OK;
}


static rp_int_t
rp_http_variable_request_body_file(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    if (r->request_body == NULL || r->request_body->temp_file == NULL) {
        v->not_found = 1;

        return RP_OK;
    }

    v->len = r->request_body->temp_file->file.name.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = r->request_body->temp_file->file.name.data;

    return RP_OK;
}


static rp_int_t
rp_http_variable_request_length(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(r->pool, RP_OFF_T_LEN);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->len = rp_sprintf(p, "%O", r->request_length) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_http_variable_request_time(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char          *p;
    rp_time_t      *tp;
    rp_msec_int_t   ms;

    p = rp_pnalloc(r->pool, RP_TIME_T_LEN + 4);
    if (p == NULL) {
        return RP_ERROR;
    }

    tp = rp_timeofday();

    ms = (rp_msec_int_t)
             ((tp->sec - r->start_sec) * 1000 + (tp->msec - r->start_msec));
    ms = rp_max(ms, 0);

    v->len = rp_sprintf(p, "%T.%03M", (time_t) ms / 1000, ms % 1000) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_http_variable_request_id(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *id;

#if (RP_OPENSSL)
    u_char   random_bytes[16];
#endif

    id = rp_pnalloc(r->pool, 32);
    if (id == NULL) {
        return RP_ERROR;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = 32;
    v->data = id;

#if (RP_OPENSSL)

    if (RAND_bytes(random_bytes, 16) == 1) {
        rp_hex_dump(id, random_bytes, 16);
        return RP_OK;
    }

    rp_ssl_error(RP_LOG_ERR, r->connection->log, 0, "RAND_bytes() failed");

#endif

    rp_sprintf(id, "%08xD%08xD%08xD%08xD",
                (uint32_t) rp_random(), (uint32_t) rp_random(),
                (uint32_t) rp_random(), (uint32_t) rp_random());

    return RP_OK;
}


static rp_int_t
rp_http_variable_connection(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(r->pool, RP_ATOMIC_T_LEN);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->len = rp_sprintf(p, "%uA", r->connection->number) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_http_variable_connection_requests(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(r->pool, RP_INT_T_LEN);
    if (p == NULL) {
        return RP_ERROR;
    }

    v->len = rp_sprintf(p, "%ui", r->connection->requests) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return RP_OK;
}


static rp_int_t
rp_http_variable_rap_version(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    v->len = sizeof(RAP_VERSION) - 1;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = (u_char *) RAP_VERSION;

    return RP_OK;
}


static rp_int_t
rp_http_variable_hostname(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    v->len = rp_cycle->hostname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = rp_cycle->hostname.data;

    return RP_OK;
}


static rp_int_t
rp_http_variable_pid(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(r->pool, RP_INT64_LEN);
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
rp_http_variable_msec(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char      *p;
    rp_time_t  *tp;

    p = rp_pnalloc(r->pool, RP_TIME_T_LEN + 4);
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
rp_http_variable_time_iso8601(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(r->pool, rp_cached_http_log_iso8601.len);
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
rp_http_variable_time_local(rp_http_request_t *r,
    rp_http_variable_value_t *v, uintptr_t data)
{
    u_char  *p;

    p = rp_pnalloc(r->pool, rp_cached_http_log_time.len);
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


void *
rp_http_map_find(rp_http_request_t *r, rp_http_map_t *map, rp_str_t *match)
{
    void        *value;
    u_char      *low;
    size_t       len;
    rp_uint_t   key;

    len = match->len;

    if (len) {
        low = rp_pnalloc(r->pool, len);
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
        rp_int_t              n;
        rp_uint_t             i;
        rp_http_map_regex_t  *reg;

        reg = map->regex;

        for (i = 0; i < map->nregex; i++) {

            n = rp_http_regex_exec(r, reg[i].regex, match);

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
rp_http_variable_not_found(rp_http_request_t *r, rp_http_variable_value_t *v,
    uintptr_t data)
{
    v->not_found = 1;
    return RP_OK;
}


rp_http_regex_t *
rp_http_regex_compile(rp_conf_t *cf, rp_regex_compile_t *rc)
{
    u_char                     *p;
    size_t                      size;
    rp_str_t                   name;
    rp_uint_t                  i, n;
    rp_http_variable_t        *v;
    rp_http_regex_t           *re;
    rp_http_regex_variable_t  *rv;
    rp_http_core_main_conf_t  *cmcf;

    rc->pool = cf->pool;

    if (rp_regex_compile(rc) != RP_OK) {
        rp_conf_log_error(RP_LOG_EMERG, cf, 0, "%V", &rc->err);
        return NULL;
    }

    re = rp_pcalloc(cf->pool, sizeof(rp_http_regex_t));
    if (re == NULL) {
        return NULL;
    }

    re->regex = rc->regex;
    re->ncaptures = rc->captures;
    re->name = rc->pattern;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);
    cmcf->ncaptures = rp_max(cmcf->ncaptures, re->ncaptures);

    n = (rp_uint_t) rc->named_captures;

    if (n == 0) {
        return re;
    }

    rv = rp_palloc(rc->pool, n * sizeof(rp_http_regex_variable_t));
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

        v = rp_http_add_variable(cf, &name, RP_HTTP_VAR_CHANGEABLE);
        if (v == NULL) {
            return NULL;
        }

        rv[i].index = rp_http_get_variable_index(cf, &name);
        if (rv[i].index == RP_ERROR) {
            return NULL;
        }

        v->get_handler = rp_http_variable_not_found;

        p += size;
    }

    return re;
}


rp_int_t
rp_http_regex_exec(rp_http_request_t *r, rp_http_regex_t *re, rp_str_t *s)
{
    rp_int_t                   rc, index;
    rp_uint_t                  i, n, len;
    rp_http_variable_value_t  *vv;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_get_module_main_conf(r, rp_http_core_module);

    if (re->ncaptures) {
        len = cmcf->ncaptures;

        if (r->captures == NULL || r->realloc_captures) {
            r->realloc_captures = 0;

            r->captures = rp_palloc(r->pool, len * sizeof(int));
            if (r->captures == NULL) {
                return RP_ERROR;
            }
        }

    } else {
        len = 0;
    }

    rc = rp_regex_exec(re->regex, s, r->captures, len);

    if (rc == RP_REGEX_NO_MATCHED) {
        return RP_DECLINED;
    }

    if (rc < 0) {
        rp_log_error(RP_LOG_ALERT, r->connection->log, 0,
                      rp_regex_exec_n " failed: %i on \"%V\" using \"%V\"",
                      rc, s, &re->name);
        return RP_ERROR;
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

#if (RP_DEBUG)
        {
        rp_http_variable_t  *v;

        v = cmcf->variables.elts;

        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http regex set $%V to \"%v\"", &v[index].name, vv);
        }
#endif
    }

    r->ncaptures = rc * 2;
    r->captures_data = s->data;

    return RP_OK;
}

#endif


rp_int_t
rp_http_variables_add_core_vars(rp_conf_t *cf)
{
    rp_http_variable_t        *cv, *v;
    rp_http_core_main_conf_t  *cmcf;

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

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
                       sizeof(rp_http_variable_t))
        != RP_OK)
    {
        return RP_ERROR;
    }

    for (cv = rp_http_core_variables; cv->name.len; cv++) {
        v = rp_http_add_variable(cf, &cv->name, cv->flags);
        if (v == NULL) {
            return RP_ERROR;
        }

        *v = *cv;
    }

    return RP_OK;
}


rp_int_t
rp_http_variables_init_vars(rp_conf_t *cf)
{
    size_t                      len;
    rp_uint_t                  i, n;
    rp_hash_key_t             *key;
    rp_hash_init_t             hash;
    rp_http_variable_t        *v, *av, *pv;
    rp_http_core_main_conf_t  *cmcf;

    /* set the handlers for the indexed http variables */

    cmcf = rp_http_conf_get_module_main_conf(cf, rp_http_core_module);

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

                av->flags |= RP_HTTP_VAR_INDEXED;
                v[i].flags = av->flags;

                av->index = i;

                if (av->get_handler == NULL
                    || (av->flags & RP_HTTP_VAR_WEAK))
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

        if (av->flags & RP_HTTP_VAR_NOHASH) {
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
