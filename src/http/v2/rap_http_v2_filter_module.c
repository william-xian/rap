
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 * Copyright (C) Ruslan Ermilov
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>
#include <rap.h>
#include <rap_http_v2_module.h>


/*
 * This returns precise number of octets for values in range 0..253
 * and estimate number for the rest, but not smaller than required.
 */

#define rap_http_v2_integer_octets(v)  (1 + (v) / 127)

#define rap_http_v2_literal_size(h)                                           \
    (rap_http_v2_integer_octets(sizeof(h) - 1) + sizeof(h) - 1)


#define RAP_HTTP_V2_NO_TRAILERS           (rap_http_v2_out_frame_t *) -1


typedef struct {
    rap_str_t      name;
    u_char         index;
    rap_uint_t     offset;
} rap_http_v2_push_header_t;


static rap_http_v2_push_header_t  rap_http_v2_push_headers[] = {
    { rap_string(":authority"), RAP_HTTP_V2_AUTHORITY_INDEX,
      offsetof(rap_http_headers_in_t, host) },

    { rap_string("accept-encoding"), RAP_HTTP_V2_ACCEPT_ENCODING_INDEX,
      offsetof(rap_http_headers_in_t, accept_encoding) },

    { rap_string("accept-language"), RAP_HTTP_V2_ACCEPT_LANGUAGE_INDEX,
      offsetof(rap_http_headers_in_t, accept_language) },

    { rap_string("user-agent"), RAP_HTTP_V2_USER_AGENT_INDEX,
      offsetof(rap_http_headers_in_t, user_agent) },
};

#define RAP_HTTP_V2_PUSH_HEADERS                                              \
    (sizeof(rap_http_v2_push_headers) / sizeof(rap_http_v2_push_header_t))


static rap_int_t rap_http_v2_push_resources(rap_http_request_t *r);
static rap_int_t rap_http_v2_push_resource(rap_http_request_t *r,
    rap_str_t *path, rap_str_t *binary);

static rap_http_v2_out_frame_t *rap_http_v2_create_headers_frame(
    rap_http_request_t *r, u_char *pos, u_char *end, rap_uint_t fin);
static rap_http_v2_out_frame_t *rap_http_v2_create_push_frame(
    rap_http_request_t *r, u_char *pos, u_char *end);
static rap_http_v2_out_frame_t *rap_http_v2_create_trailers_frame(
    rap_http_request_t *r);

static rap_chain_t *rap_http_v2_send_chain(rap_connection_t *fc,
    rap_chain_t *in, off_t limit);

static rap_chain_t *rap_http_v2_filter_get_shadow(
    rap_http_v2_stream_t *stream, rap_buf_t *buf, off_t offset, off_t size);
static rap_http_v2_out_frame_t *rap_http_v2_filter_get_data_frame(
    rap_http_v2_stream_t *stream, size_t len, rap_chain_t *first,
    rap_chain_t *last);

static rap_inline rap_int_t rap_http_v2_flow_control(
    rap_http_v2_connection_t *h2c, rap_http_v2_stream_t *stream);
static void rap_http_v2_waiting_queue(rap_http_v2_connection_t *h2c,
    rap_http_v2_stream_t *stream);

static rap_inline rap_int_t rap_http_v2_filter_send(
    rap_connection_t *fc, rap_http_v2_stream_t *stream);

static rap_int_t rap_http_v2_headers_frame_handler(
    rap_http_v2_connection_t *h2c, rap_http_v2_out_frame_t *frame);
static rap_int_t rap_http_v2_push_frame_handler(
    rap_http_v2_connection_t *h2c, rap_http_v2_out_frame_t *frame);
static rap_int_t rap_http_v2_data_frame_handler(
    rap_http_v2_connection_t *h2c, rap_http_v2_out_frame_t *frame);
static rap_inline void rap_http_v2_handle_frame(
    rap_http_v2_stream_t *stream, rap_http_v2_out_frame_t *frame);
static rap_inline void rap_http_v2_handle_stream(
    rap_http_v2_connection_t *h2c, rap_http_v2_stream_t *stream);

static void rap_http_v2_filter_cleanup(void *data);

static rap_int_t rap_http_v2_filter_init(rap_conf_t *cf);


static rap_http_module_t  rap_http_v2_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_v2_filter_init,               /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_v2_filter_module = {
    RAP_MODULE_V1,
    &rap_http_v2_filter_module_ctx,        /* module context */
    NULL,                                  /* module directives */
    RAP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RAP_MODULE_V1_PADDING
};


static rap_http_output_header_filter_pt  rap_http_next_header_filter;


static rap_int_t
rap_http_v2_header_filter(rap_http_request_t *r)
{
    u_char                     status, *pos, *start, *p, *tmp;
    size_t                     len, tmp_len;
    rap_str_t                  host, location;
    rap_uint_t                 i, port, fin;
    rap_list_part_t           *part;
    rap_table_elt_t           *header;
    rap_connection_t          *fc;
    rap_http_cleanup_t        *cln;
    rap_http_v2_stream_t      *stream;
    rap_http_v2_out_frame_t   *frame;
    rap_http_v2_connection_t  *h2c;
    rap_http_core_loc_conf_t  *clcf;
    rap_http_core_srv_conf_t  *cscf;
    u_char                     addr[RAP_SOCKADDR_STRLEN];

    static const u_char rap[5] = "\x84\xaa\x63\x55\xe7";
#if (RAP_HTTP_GZIP)
    static const u_char accept_encoding[12] =
        "\x8b\x84\x84\x2d\x69\x5b\x05\x44\x3c\x86\xaa\x6f";
#endif

    static size_t rap_ver_len = rap_http_v2_literal_size(RAP_VER);
    static u_char rap_ver[rap_http_v2_literal_size(RAP_VER)];

    static size_t rap_ver_build_len =
                                  rap_http_v2_literal_size(RAP_VER_BUILD);
    static u_char rap_ver_build[rap_http_v2_literal_size(RAP_VER_BUILD)];

    stream = r->stream;

    if (!stream) {
        return rap_http_next_header_filter(r);
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 header filter");

    if (r->header_sent) {
        return RAP_OK;
    }

    r->header_sent = 1;

    if (r != r->main) {
        return RAP_OK;
    }

    fc = r->connection;

    if (fc->error) {
        return RAP_ERROR;
    }

    if (r->method == RAP_HTTP_HEAD) {
        r->header_only = 1;
    }

    switch (r->headers_out.status) {

    case RAP_HTTP_OK:
        status = rap_http_v2_indexed(RAP_HTTP_V2_STATUS_200_INDEX);
        break;

    case RAP_HTTP_NO_CONTENT:
        r->header_only = 1;

        rap_str_null(&r->headers_out.content_type);

        r->headers_out.content_length = NULL;
        r->headers_out.content_length_n = -1;

        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;

        status = rap_http_v2_indexed(RAP_HTTP_V2_STATUS_204_INDEX);
        break;

    case RAP_HTTP_PARTIAL_CONTENT:
        status = rap_http_v2_indexed(RAP_HTTP_V2_STATUS_206_INDEX);
        break;

    case RAP_HTTP_NOT_MODIFIED:
        r->header_only = 1;
        status = rap_http_v2_indexed(RAP_HTTP_V2_STATUS_304_INDEX);
        break;

    default:
        r->headers_out.last_modified_time = -1;
        r->headers_out.last_modified = NULL;

        switch (r->headers_out.status) {

        case RAP_HTTP_BAD_REQUEST:
            status = rap_http_v2_indexed(RAP_HTTP_V2_STATUS_400_INDEX);
            break;

        case RAP_HTTP_NOT_FOUND:
            status = rap_http_v2_indexed(RAP_HTTP_V2_STATUS_404_INDEX);
            break;

        case RAP_HTTP_INTERNAL_SERVER_ERROR:
            status = rap_http_v2_indexed(RAP_HTTP_V2_STATUS_500_INDEX);
            break;

        default:
            status = 0;
        }
    }

    h2c = stream->connection;

    if (!h2c->push_disabled && !h2c->goaway
        && stream->node->id % 2 == 1
        && r->method != RAP_HTTP_HEAD)
    {
        if (rap_http_v2_push_resources(r) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    len = h2c->table_update ? 1 : 0;

    len += status ? 1 : 1 + rap_http_v2_literal_size("418");

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    if (r->headers_out.server == NULL) {

        if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_ON) {
            len += 1 + rap_ver_len;

        } else if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_BUILD) {
            len += 1 + rap_ver_build_len;

        } else {
            len += 1 + sizeof(rap);
        }
    }

    if (r->headers_out.date == NULL) {
        len += 1 + rap_http_v2_literal_size("Wed, 31 Dec 1986 18:00:00 GMT");
    }

    if (r->headers_out.content_type.len) {
        len += 1 + RAP_HTTP_V2_INT_OCTETS + r->headers_out.content_type.len;

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len += sizeof("; charset=") - 1 + r->headers_out.charset.len;
        }
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        len += 1 + rap_http_v2_integer_octets(RAP_OFF_T_LEN) + RAP_OFF_T_LEN;
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        len += 1 + rap_http_v2_literal_size("Wed, 31 Dec 1986 18:00:00 GMT");
    }

    if (r->headers_out.location && r->headers_out.location->value.len) {

        if (r->headers_out.location->value.data[0] == '/'
            && clcf->absolute_redirect)
        {
            if (clcf->server_name_in_redirect) {
                cscf = rap_http_get_module_srv_conf(r, rap_http_core_module);
                host = cscf->server_name;

            } else if (r->headers_in.server.len) {
                host = r->headers_in.server;

            } else {
                host.len = RAP_SOCKADDR_STRLEN;
                host.data = addr;

                if (rap_connection_local_sockaddr(fc, &host, 0) != RAP_OK) {
                    return RAP_ERROR;
                }
            }

            port = rap_inet_get_port(fc->local_sockaddr);

            location.len = sizeof("https://") - 1 + host.len
                           + r->headers_out.location->value.len;

            if (clcf->port_in_redirect) {

#if (RAP_HTTP_SSL)
                if (fc->ssl)
                    port = (port == 443) ? 0 : port;
                else
#endif
                    port = (port == 80) ? 0 : port;

            } else {
                port = 0;
            }

            if (port) {
                location.len += sizeof(":65535") - 1;
            }

            location.data = rap_pnalloc(r->pool, location.len);
            if (location.data == NULL) {
                return RAP_ERROR;
            }

            p = rap_cpymem(location.data, "http", sizeof("http") - 1);

#if (RAP_HTTP_SSL)
            if (fc->ssl) {
                *p++ = 's';
            }
#endif

            *p++ = ':'; *p++ = '/'; *p++ = '/';
            p = rap_cpymem(p, host.data, host.len);

            if (port) {
                p = rap_sprintf(p, ":%ui", port);
            }

            p = rap_cpymem(p, r->headers_out.location->value.data,
                              r->headers_out.location->value.len);

            /* update r->headers_out.location->value for possible logging */

            r->headers_out.location->value.len = p - location.data;
            r->headers_out.location->value.data = location.data;
            rap_str_set(&r->headers_out.location->key, "Location");
        }

        r->headers_out.location->hash = 0;

        len += 1 + RAP_HTTP_V2_INT_OCTETS + r->headers_out.location->value.len;
    }

    tmp_len = len;

#if (RAP_HTTP_GZIP)
    if (r->gzip_vary) {
        if (clcf->gzip_vary) {
            len += 1 + sizeof(accept_encoding);

        } else {
            r->gzip_vary = 0;
        }
    }
#endif

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

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

        if (header[i].key.len > RAP_HTTP_V2_MAX_FIELD) {
            rap_log_error(RAP_LOG_CRIT, fc->log, 0,
                          "too long response header name: \"%V\"",
                          &header[i].key);
            return RAP_ERROR;
        }

        if (header[i].value.len > RAP_HTTP_V2_MAX_FIELD) {
            rap_log_error(RAP_LOG_CRIT, fc->log, 0,
                          "too long response header value: \"%V: %V\"",
                          &header[i].key, &header[i].value);
            return RAP_ERROR;
        }

        len += 1 + RAP_HTTP_V2_INT_OCTETS + header[i].key.len
                 + RAP_HTTP_V2_INT_OCTETS + header[i].value.len;

        if (header[i].key.len > tmp_len) {
            tmp_len = header[i].key.len;
        }

        if (header[i].value.len > tmp_len) {
            tmp_len = header[i].value.len;
        }
    }

    tmp = rap_palloc(r->pool, tmp_len);
    pos = rap_pnalloc(r->pool, len);

    if (pos == NULL || tmp == NULL) {
        return RAP_ERROR;
    }

    start = pos;

    if (h2c->table_update) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 table size update: 0");
        *pos++ = (1 << 5) | 0;
        h2c->table_update = 0;
    }

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 output header: \":status: %03ui\"",
                   r->headers_out.status);

    if (status) {
        *pos++ = status;

    } else {
        *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_STATUS_INDEX);
        *pos++ = RAP_HTTP_V2_ENCODE_RAW | 3;
        pos = rap_sprintf(pos, "%03ui", r->headers_out.status);
    }

    if (r->headers_out.server == NULL) {

        if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_ON) {
            rap_log_debug1(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output header: \"server: %s\"",
                           RAP_VER);

        } else if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_BUILD) {
            rap_log_debug1(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output header: \"server: %s\"",
                           RAP_VER_BUILD);

        } else {
            rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output header: \"server: rap\"");
        }

        *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_SERVER_INDEX);

        if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_ON) {
            if (rap_ver[0] == '\0') {
                p = rap_http_v2_write_value(rap_ver, (u_char *) RAP_VER,
                                            sizeof(RAP_VER) - 1, tmp);
                rap_ver_len = p - rap_ver;
            }

            pos = rap_cpymem(pos, rap_ver, rap_ver_len);

        } else if (clcf->server_tokens == RAP_HTTP_SERVER_TOKENS_BUILD) {
            if (rap_ver_build[0] == '\0') {
                p = rap_http_v2_write_value(rap_ver_build,
                                            (u_char *) RAP_VER_BUILD,
                                            sizeof(RAP_VER_BUILD) - 1, tmp);
                rap_ver_build_len = p - rap_ver_build;
            }

            pos = rap_cpymem(pos, rap_ver_build, rap_ver_build_len);

        } else {
            pos = rap_cpymem(pos, rap, sizeof(rap));
        }
    }

    if (r->headers_out.date == NULL) {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"date: %V\"",
                       &rap_cached_http_time);

        *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_DATE_INDEX);
        pos = rap_http_v2_write_value(pos, rap_cached_http_time.data,
                                      rap_cached_http_time.len, tmp);
    }

    if (r->headers_out.content_type.len) {
        *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_CONTENT_TYPE_INDEX);

        if (r->headers_out.content_type_len == r->headers_out.content_type.len
            && r->headers_out.charset.len)
        {
            len = r->headers_out.content_type.len + sizeof("; charset=") - 1
                  + r->headers_out.charset.len;

            p = rap_pnalloc(r->pool, len);
            if (p == NULL) {
                return RAP_ERROR;
            }

            p = rap_cpymem(p, r->headers_out.content_type.data,
                           r->headers_out.content_type.len);

            p = rap_cpymem(p, "; charset=", sizeof("; charset=") - 1);

            p = rap_cpymem(p, r->headers_out.charset.data,
                           r->headers_out.charset.len);

            /* updated r->headers_out.content_type is also needed for logging */

            r->headers_out.content_type.len = len;
            r->headers_out.content_type.data = p - len;
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"content-type: %V\"",
                       &r->headers_out.content_type);

        pos = rap_http_v2_write_value(pos, r->headers_out.content_type.data,
                                      r->headers_out.content_type.len, tmp);
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"content-length: %O\"",
                       r->headers_out.content_length_n);

        *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_CONTENT_LENGTH_INDEX);

        p = pos;
        pos = rap_sprintf(pos + 1, "%O", r->headers_out.content_length_n);
        *p = RAP_HTTP_V2_ENCODE_RAW | (u_char) (pos - p - 1);
    }

    if (r->headers_out.last_modified == NULL
        && r->headers_out.last_modified_time != -1)
    {
        *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_LAST_MODIFIED_INDEX);

        rap_http_time(pos, r->headers_out.last_modified_time);
        len = sizeof("Wed, 31 Dec 1986 18:00:00 GMT") - 1;

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"last-modified: %*s\"",
                       len, pos);

        /*
         * Date will always be encoded using huffman in the temporary buffer,
         * so it's safe here to use src and dst pointing to the same address.
         */
        pos = rap_http_v2_write_value(pos, pos, len, tmp);
    }

    if (r->headers_out.location && r->headers_out.location->value.len) {
        rap_log_debug1(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"location: %V\"",
                       &r->headers_out.location->value);

        *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_LOCATION_INDEX);
        pos = rap_http_v2_write_value(pos, r->headers_out.location->value.data,
                                      r->headers_out.location->value.len, tmp);
    }

#if (RAP_HTTP_GZIP)
    if (r->gzip_vary) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 output header: \"vary: Accept-Encoding\"");

        *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_VARY_INDEX);
        pos = rap_cpymem(pos, accept_encoding, sizeof(accept_encoding));
    }
#endif

    part = &r->headers_out.headers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

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

#if (RAP_DEBUG)
        if (fc->log->log_level & RAP_LOG_DEBUG_HTTP) {
            rap_strlow(tmp, header[i].key.data, header[i].key.len);

            rap_log_debug3(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output header: \"%*s: %V\"",
                           header[i].key.len, tmp, &header[i].value);
        }
#endif

        *pos++ = 0;

        pos = rap_http_v2_write_name(pos, header[i].key.data,
                                     header[i].key.len, tmp);

        pos = rap_http_v2_write_value(pos, header[i].value.data,
                                      header[i].value.len, tmp);
    }

    fin = r->header_only
          || (r->headers_out.content_length_n == 0 && !r->expect_trailers);

    frame = rap_http_v2_create_headers_frame(r, start, pos, fin);
    if (frame == NULL) {
        return RAP_ERROR;
    }

    rap_http_v2_queue_blocked_frame(h2c, frame);

    stream->queued++;

    cln = rap_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return RAP_ERROR;
    }

    cln->handler = rap_http_v2_filter_cleanup;
    cln->data = stream;

    fc->send_chain = rap_http_v2_send_chain;
    fc->need_last_buf = 1;

    return rap_http_v2_filter_send(fc, stream);
}


static rap_int_t
rap_http_v2_push_resources(rap_http_request_t *r)
{
    u_char                     *start, *end, *last;
    rap_int_t                   rc;
    rap_str_t                   path;
    rap_uint_t                  i, push;
    rap_table_elt_t           **h;
    rap_http_v2_loc_conf_t     *h2lcf;
    rap_http_complex_value_t   *pushes;
    rap_str_t                   binary[RAP_HTTP_V2_PUSH_HEADERS];

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http2 push resources");

    rap_memzero(binary, RAP_HTTP_V2_PUSH_HEADERS * sizeof(rap_str_t));

    h2lcf = rap_http_get_module_loc_conf(r, rap_http_v2_module);

    if (h2lcf->pushes) {
        pushes = h2lcf->pushes->elts;

        for (i = 0; i < h2lcf->pushes->nelts; i++) {

            if (rap_http_complex_value(r, &pushes[i], &path) != RAP_OK) {
                return RAP_ERROR;
            }

            if (path.len == 0) {
                continue;
            }

            if (path.len == 3 && rap_strncmp(path.data, "off", 3) == 0) {
                continue;
            }

            rc = rap_http_v2_push_resource(r, &path, binary);

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            if (rc == RAP_ABORT) {
                return RAP_OK;
            }

            /* RAP_OK, RAP_DECLINED */
        }
    }

    if (!h2lcf->push_preload) {
        return RAP_OK;
    }

    h = r->headers_out.link.elts;

    for (i = 0; i < r->headers_out.link.nelts; i++) {

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http2 parse link: \"%V\"", &h[i]->value);

        start = h[i]->value.data;
        end = h[i]->value.data + h[i]->value.len;

    next_link:

        while (start < end && *start == ' ') { start++; }

        if (start == end || *start++ != '<') {
            continue;
        }

        while (start < end && *start == ' ') { start++; }

        for (last = start; last < end && *last != '>'; last++) {
            /* void */
        }

        if (last == start || last == end) {
            continue;
        }

        path.len = last - start;
        path.data = start;

        start = last + 1;

        while (start < end && *start == ' ') { start++; }

        if (start == end) {
            continue;
        }

        if (*start == ',') {
            start++;
            goto next_link;
        }

        if (*start++ != ';') {
            continue;
        }

        last = rap_strlchr(start, end, ',');

        if (last == NULL) {
            last = end;
        }

        push = 0;

        for ( ;; ) {

            while (start < last && *start == ' ') { start++; }

            if (last - start >= 6
                && rap_strncasecmp(start, (u_char *) "nopush", 6) == 0)
            {
                start += 6;

                if (start == last || *start == ' ' || *start == ';') {
                    push = 0;
                    break;
                }

                goto next_param;
            }

            if (last - start >= 11
                && rap_strncasecmp(start, (u_char *) "rel=preload", 11) == 0)
            {
                start += 11;

                if (start == last || *start == ' ' || *start == ';') {
                    push = 1;
                }

                goto next_param;
            }

            if (last - start >= 4
                && rap_strncasecmp(start, (u_char *) "rel=", 4) == 0)
            {
                start += 4;

                while (start < last && *start == ' ') { start++; }

                if (start == last || *start++ != '"') {
                    goto next_param;
                }

                for ( ;; ) {

                    while (start < last && *start == ' ') { start++; }

                    if (last - start >= 7
                        && rap_strncasecmp(start, (u_char *) "preload", 7) == 0)
                    {
                        start += 7;

                        if (start < last && (*start == ' ' || *start == '"')) {
                            push = 1;
                            break;
                        }
                    }

                    while (start < last && *start != ' ' && *start != '"') {
                        start++;
                    }

                    if (start == last) {
                        break;
                    }

                    if (*start == '"') {
                        break;
                    }

                    start++;
                }
            }

        next_param:

            start = rap_strlchr(start, last, ';');

            if (start == NULL) {
                break;
            }

            start++;
        }

        if (push) {
            while (path.len && path.data[path.len - 1] == ' ') {
                path.len--;
            }
        }

        if (push && path.len
            && !(path.len > 1 && path.data[0] == '/' && path.data[1] == '/'))
        {
            rc = rap_http_v2_push_resource(r, &path, binary);

            if (rc == RAP_ERROR) {
                return RAP_ERROR;
            }

            if (rc == RAP_ABORT) {
                return RAP_OK;
            }

            /* RAP_OK, RAP_DECLINED */
        }

        if (last < end) {
            start = last + 1;
            goto next_link;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_http_v2_push_resource(rap_http_request_t *r, rap_str_t *path,
    rap_str_t *binary)
{
    u_char                      *start, *pos, *tmp;
    size_t                       len;
    rap_str_t                   *value;
    rap_uint_t                   i;
    rap_table_elt_t            **h;
    rap_connection_t            *fc;
    rap_http_v2_stream_t        *stream;
    rap_http_v2_out_frame_t     *frame;
    rap_http_v2_connection_t    *h2c;
    rap_http_v2_push_header_t   *ph;

    fc = r->connection;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0, "http2 push resource");

    stream = r->stream;
    h2c = stream->connection;

    if (!rap_path_separator(path->data[0])) {
        rap_log_error(RAP_LOG_WARN, fc->log, 0,
                      "non-absolute path \"%V\" not pushed", path);
        return RAP_DECLINED;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2 pushing:%ui limit:%ui",
                   h2c->pushing, h2c->concurrent_pushes);

    if (h2c->pushing >= h2c->concurrent_pushes) {
        return RAP_ABORT;
    }

    if (h2c->last_push == 0x7ffffffe) {
        return RAP_ABORT;
    }

    if (path->len > RAP_HTTP_V2_MAX_FIELD) {
        return RAP_DECLINED;
    }

    if (r->headers_in.host == NULL) {
        return RAP_ABORT;
    }

    ph = rap_http_v2_push_headers;

    len = rap_max(r->schema.len, path->len);

    if (binary[0].len) {
        tmp = rap_palloc(r->pool, len);
        if (tmp == NULL) {
            return RAP_ERROR;
        }

    } else {
        for (i = 0; i < RAP_HTTP_V2_PUSH_HEADERS; i++) {
            h = (rap_table_elt_t **) ((char *) &r->headers_in + ph[i].offset);

            if (*h) {
                len = rap_max(len, (*h)->value.len);
            }
        }

        tmp = rap_palloc(r->pool, len);
        if (tmp == NULL) {
            return RAP_ERROR;
        }

        for (i = 0; i < RAP_HTTP_V2_PUSH_HEADERS; i++) {
            h = (rap_table_elt_t **) ((char *) &r->headers_in + ph[i].offset);

            if (*h == NULL) {
                continue;
            }

            value = &(*h)->value;

            len = 1 + RAP_HTTP_V2_INT_OCTETS + value->len;

            pos = rap_pnalloc(r->pool, len);
            if (pos == NULL) {
                return RAP_ERROR;
            }

            binary[i].data = pos;

            *pos++ = rap_http_v2_inc_indexed(ph[i].index);
            pos = rap_http_v2_write_value(pos, value->data, value->len, tmp);

            binary[i].len = pos - binary[i].data;
        }
    }

    len = (h2c->table_update ? 1 : 0)
          + 1
          + 1 + RAP_HTTP_V2_INT_OCTETS + path->len
          + 1 + RAP_HTTP_V2_INT_OCTETS + r->schema.len;

    for (i = 0; i < RAP_HTTP_V2_PUSH_HEADERS; i++) {
        len += binary[i].len;
    }

    pos = rap_pnalloc(r->pool, len);
    if (pos == NULL) {
        return RAP_ERROR;
    }

    start = pos;

    if (h2c->table_update) {
        rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 table size update: 0");
        *pos++ = (1 << 5) | 0;
        h2c->table_update = 0;
    }

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 push header: \":method: GET\"");

    *pos++ = rap_http_v2_indexed(RAP_HTTP_V2_METHOD_GET_INDEX);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 push header: \":path: %V\"", path);

    *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_PATH_INDEX);
    pos = rap_http_v2_write_value(pos, path->data, path->len, tmp);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                   "http2 push header: \":scheme: %V\"", &r->schema);

    if (r->schema.len == 5 && rap_strncmp(r->schema.data, "https", 5) == 0) {
        *pos++ = rap_http_v2_indexed(RAP_HTTP_V2_SCHEME_HTTPS_INDEX);

    } else if (r->schema.len == 4
               && rap_strncmp(r->schema.data, "http", 4) == 0)
    {
        *pos++ = rap_http_v2_indexed(RAP_HTTP_V2_SCHEME_HTTP_INDEX);

    } else {
        *pos++ = rap_http_v2_inc_indexed(RAP_HTTP_V2_SCHEME_HTTP_INDEX);
        pos = rap_http_v2_write_value(pos, r->schema.data, r->schema.len, tmp);
    }

    for (i = 0; i < RAP_HTTP_V2_PUSH_HEADERS; i++) {
        h = (rap_table_elt_t **) ((char *) &r->headers_in + ph[i].offset);

        if (*h == NULL) {
            continue;
        }

        rap_log_debug2(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                       "http2 push header: \"%V: %V\"",
                       &ph[i].name, &(*h)->value);

        pos = rap_cpymem(pos, binary[i].data, binary[i].len);
    }

    frame = rap_http_v2_create_push_frame(r, start, pos);
    if (frame == NULL) {
        return RAP_ERROR;
    }

    rap_http_v2_queue_blocked_frame(h2c, frame);

    stream->queued++;

    stream = rap_http_v2_push_stream(stream, path);

    if (stream) {
        stream->request->request_length = pos - start;
        return RAP_OK;
    }

    return RAP_ERROR;
}


static rap_http_v2_out_frame_t *
rap_http_v2_create_headers_frame(rap_http_request_t *r, u_char *pos,
    u_char *end, rap_uint_t fin)
{
    u_char                    type, flags;
    size_t                    rest, frame_size;
    rap_buf_t                *b;
    rap_chain_t              *cl, **ll;
    rap_http_v2_stream_t     *stream;
    rap_http_v2_out_frame_t  *frame;

    stream = r->stream;
    rest = end - pos;

    frame = rap_palloc(r->pool, sizeof(rap_http_v2_out_frame_t));
    if (frame == NULL) {
        return NULL;
    }

    frame->handler = rap_http_v2_headers_frame_handler;
    frame->stream = stream;
    frame->length = rest;
    frame->blocked = 1;
    frame->fin = fin;

    ll = &frame->first;

    type = RAP_HTTP_V2_HEADERS_FRAME;
    flags = fin ? RAP_HTTP_V2_END_STREAM_FLAG : RAP_HTTP_V2_NO_FLAG;
    frame_size = stream->connection->frame_size;

    for ( ;; ) {
        if (rest <= frame_size) {
            frame_size = rest;
            flags |= RAP_HTTP_V2_END_HEADERS_FLAG;
        }

        b = rap_create_temp_buf(r->pool, RAP_HTTP_V2_FRAME_HEADER_SIZE);
        if (b == NULL) {
            return NULL;
        }

        b->last = rap_http_v2_write_len_and_type(b->last, frame_size, type);
        *b->last++ = flags;
        b->last = rap_http_v2_write_sid(b->last, stream->node->id);

        b->tag = (rap_buf_tag_t) &rap_http_v2_module;

        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;

        *ll = cl;
        ll = &cl->next;

        b = rap_calloc_buf(r->pool);
        if (b == NULL) {
            return NULL;
        }

        b->pos = pos;

        pos += frame_size;

        b->last = pos;
        b->start = b->pos;
        b->end = b->last;
        b->temporary = 1;

        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;

        *ll = cl;
        ll = &cl->next;

        rest -= frame_size;

        if (rest) {
            frame->length += RAP_HTTP_V2_FRAME_HEADER_SIZE;

            type = RAP_HTTP_V2_CONTINUATION_FRAME;
            flags = RAP_HTTP_V2_NO_FLAG;
            continue;
        }

        b->last_buf = fin;
        cl->next = NULL;
        frame->last = cl;

        rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http2:%ui create HEADERS frame %p: len:%uz fin:%ui",
                       stream->node->id, frame, frame->length, fin);

        return frame;
    }
}


static rap_http_v2_out_frame_t *
rap_http_v2_create_push_frame(rap_http_request_t *r, u_char *pos, u_char *end)
{
    u_char                     type, flags;
    size_t                     rest, frame_size, len;
    rap_buf_t                 *b;
    rap_chain_t               *cl, **ll;
    rap_http_v2_stream_t      *stream;
    rap_http_v2_out_frame_t   *frame;
    rap_http_v2_connection_t  *h2c;

    stream = r->stream;
    h2c = stream->connection;
    rest = RAP_HTTP_V2_STREAM_ID_SIZE + (end - pos);

    frame = rap_palloc(r->pool, sizeof(rap_http_v2_out_frame_t));
    if (frame == NULL) {
        return NULL;
    }

    frame->handler = rap_http_v2_push_frame_handler;
    frame->stream = stream;
    frame->length = rest;
    frame->blocked = 1;
    frame->fin = 0;

    ll = &frame->first;

    type = RAP_HTTP_V2_PUSH_PROMISE_FRAME;
    flags = RAP_HTTP_V2_NO_FLAG;
    frame_size = h2c->frame_size;

    for ( ;; ) {
        if (rest <= frame_size) {
            frame_size = rest;
            flags |= RAP_HTTP_V2_END_HEADERS_FLAG;
        }

        b = rap_create_temp_buf(r->pool,
                                RAP_HTTP_V2_FRAME_HEADER_SIZE
                                + ((type == RAP_HTTP_V2_PUSH_PROMISE_FRAME)
                                   ? RAP_HTTP_V2_STREAM_ID_SIZE : 0));
        if (b == NULL) {
            return NULL;
        }

        b->last = rap_http_v2_write_len_and_type(b->last, frame_size, type);
        *b->last++ = flags;
        b->last = rap_http_v2_write_sid(b->last, stream->node->id);

        b->tag = (rap_buf_tag_t) &rap_http_v2_module;

        if (type == RAP_HTTP_V2_PUSH_PROMISE_FRAME) {
            h2c->last_push += 2;

            b->last = rap_http_v2_write_sid(b->last, h2c->last_push);
            len = frame_size - RAP_HTTP_V2_STREAM_ID_SIZE;

        } else {
            len = frame_size;
        }

        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;

        *ll = cl;
        ll = &cl->next;

        b = rap_calloc_buf(r->pool);
        if (b == NULL) {
            return NULL;
        }

        b->pos = pos;

        pos += len;

        b->last = pos;
        b->start = b->pos;
        b->end = b->last;
        b->temporary = 1;

        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;

        *ll = cl;
        ll = &cl->next;

        rest -= frame_size;

        if (rest) {
            frame->length += RAP_HTTP_V2_FRAME_HEADER_SIZE;

            type = RAP_HTTP_V2_CONTINUATION_FRAME;
            continue;
        }

        cl->next = NULL;
        frame->last = cl;

        rap_log_debug4(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http2:%ui create PUSH_PROMISE frame %p: "
                       "sid:%ui len:%uz",
                       stream->node->id, frame, h2c->last_push,
                       frame->length);

        return frame;
    }
}


static rap_http_v2_out_frame_t *
rap_http_v2_create_trailers_frame(rap_http_request_t *r)
{
    u_char            *pos, *start, *tmp;
    size_t             len, tmp_len;
    rap_uint_t         i;
    rap_list_part_t   *part;
    rap_table_elt_t   *header;
    rap_connection_t  *fc;

    fc = r->connection;
    len = 0;
    tmp_len = 0;

    part = &r->headers_out.trailers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

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

        if (header[i].key.len > RAP_HTTP_V2_MAX_FIELD) {
            rap_log_error(RAP_LOG_CRIT, fc->log, 0,
                          "too long response trailer name: \"%V\"",
                          &header[i].key);
            return NULL;
        }

        if (header[i].value.len > RAP_HTTP_V2_MAX_FIELD) {
            rap_log_error(RAP_LOG_CRIT, fc->log, 0,
                          "too long response trailer value: \"%V: %V\"",
                          &header[i].key, &header[i].value);
            return NULL;
        }

        len += 1 + RAP_HTTP_V2_INT_OCTETS + header[i].key.len
                 + RAP_HTTP_V2_INT_OCTETS + header[i].value.len;

        if (header[i].key.len > tmp_len) {
            tmp_len = header[i].key.len;
        }

        if (header[i].value.len > tmp_len) {
            tmp_len = header[i].value.len;
        }
    }

    if (len == 0) {
        return RAP_HTTP_V2_NO_TRAILERS;
    }

    tmp = rap_palloc(r->pool, tmp_len);
    pos = rap_pnalloc(r->pool, len);

    if (pos == NULL || tmp == NULL) {
        return NULL;
    }

    start = pos;

    part = &r->headers_out.trailers.part;
    header = part->elts;

    for (i = 0; /* void */; i++) {

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

#if (RAP_DEBUG)
        if (fc->log->log_level & RAP_LOG_DEBUG_HTTP) {
            rap_strlow(tmp, header[i].key.data, header[i].key.len);

            rap_log_debug3(RAP_LOG_DEBUG_HTTP, fc->log, 0,
                           "http2 output trailer: \"%*s: %V\"",
                           header[i].key.len, tmp, &header[i].value);
        }
#endif

        *pos++ = 0;

        pos = rap_http_v2_write_name(pos, header[i].key.data,
                                     header[i].key.len, tmp);

        pos = rap_http_v2_write_value(pos, header[i].value.data,
                                      header[i].value.len, tmp);
    }

    return rap_http_v2_create_headers_frame(r, start, pos, 1);
}


static rap_chain_t *
rap_http_v2_send_chain(rap_connection_t *fc, rap_chain_t *in, off_t limit)
{
    off_t                      size, offset;
    size_t                     rest, frame_size;
    rap_chain_t               *cl, *out, **ln;
    rap_http_request_t        *r;
    rap_http_v2_stream_t      *stream;
    rap_http_v2_loc_conf_t    *h2lcf;
    rap_http_v2_out_frame_t   *frame, *trailers;
    rap_http_v2_connection_t  *h2c;

    r = fc->data;
    stream = r->stream;

#if (RAP_SUPPRESS_WARN)
    size = 0;
#endif

    while (in) {
        size = rap_buf_size(in->buf);

        if (size || in->buf->last_buf) {
            break;
        }

        in = in->next;
    }

    if (in == NULL || stream->out_closed) {

        if (size) {
            rap_log_error(RAP_LOG_ERR, fc->log, 0,
                          "output on closed stream");
            return RAP_CHAIN_ERROR;
        }

        if (stream->queued) {
            fc->write->active = 1;
            fc->write->ready = 0;

        } else {
            fc->buffered &= ~RAP_HTTP_V2_BUFFERED;
        }

        return NULL;
    }

    h2c = stream->connection;

    if (size && rap_http_v2_flow_control(h2c, stream) == RAP_DECLINED) {
        fc->write->active = 1;
        fc->write->ready = 0;
        return in;
    }

    if (in->buf->tag == (rap_buf_tag_t) &rap_http_v2_filter_get_shadow) {
        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RAP_CHAIN_ERROR;
        }

        cl->buf = in->buf;
        in->buf = cl->buf->shadow;

        offset = rap_buf_in_memory(in->buf)
                 ? (cl->buf->pos - in->buf->pos)
                 : (cl->buf->file_pos - in->buf->file_pos);

        cl->next = stream->free_bufs;
        stream->free_bufs = cl;

    } else {
        offset = 0;
    }

    if (limit == 0 || limit > (off_t) h2c->send_window) {
        limit = h2c->send_window;
    }

    if (limit > stream->send_window) {
        limit = (stream->send_window > 0) ? stream->send_window : 0;
    }

    h2lcf = rap_http_get_module_loc_conf(r, rap_http_v2_module);

    frame_size = (h2lcf->chunk_size < h2c->frame_size)
                 ? h2lcf->chunk_size : h2c->frame_size;

    trailers = RAP_HTTP_V2_NO_TRAILERS;

#if (RAP_SUPPRESS_WARN)
    cl = NULL;
#endif

    for ( ;; ) {
        if ((off_t) frame_size > limit) {
            frame_size = (size_t) limit;
        }

        ln = &out;
        rest = frame_size;

        while ((off_t) rest >= size) {

            if (offset) {
                cl = rap_http_v2_filter_get_shadow(stream, in->buf,
                                                   offset, size);
                if (cl == NULL) {
                    return RAP_CHAIN_ERROR;
                }

                offset = 0;

            } else {
                cl = rap_alloc_chain_link(r->pool);
                if (cl == NULL) {
                    return RAP_CHAIN_ERROR;
                }

                cl->buf = in->buf;
            }

            *ln = cl;
            ln = &cl->next;

            rest -= (size_t) size;
            in = in->next;

            if (in == NULL) {
                frame_size -= rest;
                rest = 0;
                break;
            }

            size = rap_buf_size(in->buf);
        }

        if (rest) {
            cl = rap_http_v2_filter_get_shadow(stream, in->buf, offset, rest);
            if (cl == NULL) {
                return RAP_CHAIN_ERROR;
            }

            cl->buf->flush = 0;
            cl->buf->last_buf = 0;

            *ln = cl;

            offset += rest;
            size -= rest;
        }

        if (cl->buf->last_buf) {
            trailers = rap_http_v2_create_trailers_frame(r);
            if (trailers == NULL) {
                return RAP_CHAIN_ERROR;
            }

            if (trailers != RAP_HTTP_V2_NO_TRAILERS) {
                cl->buf->last_buf = 0;
            }
        }

        if (frame_size || cl->buf->last_buf) {
            frame = rap_http_v2_filter_get_data_frame(stream, frame_size,
                                                      out, cl);
            if (frame == NULL) {
                return RAP_CHAIN_ERROR;
            }

            rap_http_v2_queue_frame(h2c, frame);

            h2c->send_window -= frame_size;

            stream->send_window -= frame_size;
            stream->queued++;
        }

        if (in == NULL) {

            if (trailers != RAP_HTTP_V2_NO_TRAILERS) {
                rap_http_v2_queue_frame(h2c, trailers);
                stream->queued++;
            }

            break;
        }

        limit -= frame_size;

        if (limit == 0) {
            break;
        }
    }

    if (offset) {
        cl = rap_http_v2_filter_get_shadow(stream, in->buf, offset, size);
        if (cl == NULL) {
            return RAP_CHAIN_ERROR;
        }

        in->buf = cl->buf;
        rap_free_chain(r->pool, cl);
    }

    if (rap_http_v2_filter_send(fc, stream) == RAP_ERROR) {
        return RAP_CHAIN_ERROR;
    }

    if (in && rap_http_v2_flow_control(h2c, stream) == RAP_DECLINED) {
        fc->write->active = 1;
        fc->write->ready = 0;
    }

    return in;
}


static rap_chain_t *
rap_http_v2_filter_get_shadow(rap_http_v2_stream_t *stream, rap_buf_t *buf,
    off_t offset, off_t size)
{
    rap_buf_t    *chunk;
    rap_chain_t  *cl;

    cl = rap_chain_get_free_buf(stream->request->pool, &stream->free_bufs);
    if (cl == NULL) {
        return NULL;
    }

    chunk = cl->buf;

    rap_memcpy(chunk, buf, sizeof(rap_buf_t));

    chunk->tag = (rap_buf_tag_t) &rap_http_v2_filter_get_shadow;
    chunk->shadow = buf;

    if (rap_buf_in_memory(chunk)) {
        chunk->pos += offset;
        chunk->last = chunk->pos + size;
    }

    if (chunk->in_file) {
        chunk->file_pos += offset;
        chunk->file_last = chunk->file_pos + size;
    }

    return cl;
}


static rap_http_v2_out_frame_t *
rap_http_v2_filter_get_data_frame(rap_http_v2_stream_t *stream,
    size_t len, rap_chain_t *first, rap_chain_t *last)
{
    u_char                     flags;
    rap_buf_t                 *buf;
    rap_chain_t               *cl;
    rap_http_v2_out_frame_t   *frame;
    rap_http_v2_connection_t  *h2c;

    frame = stream->free_frames;
    h2c = stream->connection;

    if (frame) {
        stream->free_frames = frame->next;

    } else if (h2c->frames < 10000) {
        frame = rap_palloc(stream->request->pool,
                           sizeof(rap_http_v2_out_frame_t));
        if (frame == NULL) {
            return NULL;
        }

        stream->frames++;
        h2c->frames++;

    } else {
        rap_log_error(RAP_LOG_INFO, h2c->connection->log, 0,
                      "http2 flood detected");

        h2c->connection->error = 1;
        return NULL;
    }

    flags = last->buf->last_buf ? RAP_HTTP_V2_END_STREAM_FLAG : 0;

    rap_log_debug4(RAP_LOG_DEBUG_HTTP, stream->request->connection->log, 0,
                   "http2:%ui create DATA frame %p: len:%uz flags:%ui",
                   stream->node->id, frame, len, (rap_uint_t) flags);

    cl = rap_chain_get_free_buf(stream->request->pool,
                                &stream->free_frame_headers);
    if (cl == NULL) {
        return NULL;
    }

    buf = cl->buf;

    if (buf->start == NULL) {
        buf->start = rap_palloc(stream->request->pool,
                                RAP_HTTP_V2_FRAME_HEADER_SIZE);
        if (buf->start == NULL) {
            return NULL;
        }

        buf->end = buf->start + RAP_HTTP_V2_FRAME_HEADER_SIZE;
        buf->last = buf->end;

        buf->tag = (rap_buf_tag_t) &rap_http_v2_module;
        buf->memory = 1;
    }

    buf->pos = buf->start;
    buf->last = buf->pos;

    buf->last = rap_http_v2_write_len_and_type(buf->last, len,
                                               RAP_HTTP_V2_DATA_FRAME);
    *buf->last++ = flags;

    buf->last = rap_http_v2_write_sid(buf->last, stream->node->id);

    cl->next = first;
    first = cl;

    last->buf->flush = 1;

    frame->first = first;
    frame->last = last;
    frame->handler = rap_http_v2_data_frame_handler;
    frame->stream = stream;
    frame->length = len;
    frame->blocked = 0;
    frame->fin = last->buf->last_buf;

    return frame;
}


static rap_inline rap_int_t
rap_http_v2_flow_control(rap_http_v2_connection_t *h2c,
    rap_http_v2_stream_t *stream)
{
    rap_log_debug3(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2:%ui windows: conn:%uz stream:%z",
                   stream->node->id, h2c->send_window, stream->send_window);

    if (stream->send_window <= 0) {
        stream->exhausted = 1;
        return RAP_DECLINED;
    }

    if (h2c->send_window == 0) {
        rap_http_v2_waiting_queue(h2c, stream);
        return RAP_DECLINED;
    }

    return RAP_OK;
}


static void
rap_http_v2_waiting_queue(rap_http_v2_connection_t *h2c,
    rap_http_v2_stream_t *stream)
{
    rap_queue_t           *q;
    rap_http_v2_stream_t  *s;

    if (stream->waiting) {
        return;
    }

    stream->waiting = 1;

    for (q = rap_queue_last(&h2c->waiting);
         q != rap_queue_sentinel(&h2c->waiting);
         q = rap_queue_prev(q))
    {
        s = rap_queue_data(q, rap_http_v2_stream_t, queue);

        if (s->node->rank < stream->node->rank
            || (s->node->rank == stream->node->rank
                && s->node->rel_weight >= stream->node->rel_weight))
        {
            break;
        }
    }

    rap_queue_insert_after(q, &stream->queue);
}


static rap_inline rap_int_t
rap_http_v2_filter_send(rap_connection_t *fc, rap_http_v2_stream_t *stream)
{
    stream->blocked = 1;

    if (rap_http_v2_send_output_queue(stream->connection) == RAP_ERROR) {
        fc->error = 1;
        return RAP_ERROR;
    }

    stream->blocked = 0;

    if (stream->queued) {
        fc->buffered |= RAP_HTTP_V2_BUFFERED;
        fc->write->active = 1;
        fc->write->ready = 0;
        return RAP_AGAIN;
    }

    fc->buffered &= ~RAP_HTTP_V2_BUFFERED;

    return RAP_OK;
}


static rap_int_t
rap_http_v2_headers_frame_handler(rap_http_v2_connection_t *h2c,
    rap_http_v2_out_frame_t *frame)
{
    rap_chain_t           *cl, *ln;
    rap_http_v2_stream_t  *stream;

    stream = frame->stream;
    cl = frame->first;

    for ( ;; ) {
        if (cl->buf->pos != cl->buf->last) {
            frame->first = cl;

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui HEADERS frame %p was sent partially",
                           stream->node->id, frame);

            return RAP_AGAIN;
        }

        ln = cl->next;

        if (cl->buf->tag == (rap_buf_tag_t) &rap_http_v2_module) {
            cl->next = stream->free_frame_headers;
            stream->free_frame_headers = cl;

        } else {
            cl->next = stream->free_bufs;
            stream->free_bufs = cl;
        }

        if (cl == frame->last) {
            break;
        }

        cl = ln;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2:%ui HEADERS frame %p was sent",
                   stream->node->id, frame);

    stream->request->header_size += RAP_HTTP_V2_FRAME_HEADER_SIZE
                                    + frame->length;

    h2c->payload_bytes += frame->length;

    rap_http_v2_handle_frame(stream, frame);

    rap_http_v2_handle_stream(h2c, stream);

    return RAP_OK;
}


static rap_int_t
rap_http_v2_push_frame_handler(rap_http_v2_connection_t *h2c,
    rap_http_v2_out_frame_t *frame)
{
    rap_chain_t           *cl, *ln;
    rap_http_v2_stream_t  *stream;

    stream = frame->stream;
    cl = frame->first;

    for ( ;; ) {
        if (cl->buf->pos != cl->buf->last) {
            frame->first = cl;

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui PUSH_PROMISE frame %p was sent partially",
                           stream->node->id, frame);

            return RAP_AGAIN;
        }

        ln = cl->next;

        if (cl->buf->tag == (rap_buf_tag_t) &rap_http_v2_module) {
            cl->next = stream->free_frame_headers;
            stream->free_frame_headers = cl;

        } else {
            cl->next = stream->free_bufs;
            stream->free_bufs = cl;
        }

        if (cl == frame->last) {
            break;
        }

        cl = ln;
    }

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2:%ui PUSH_PROMISE frame %p was sent",
                   stream->node->id, frame);

    stream->request->header_size += RAP_HTTP_V2_FRAME_HEADER_SIZE
                                    + frame->length;

    h2c->payload_bytes += frame->length;

    rap_http_v2_handle_frame(stream, frame);

    rap_http_v2_handle_stream(h2c, stream);

    return RAP_OK;
}


static rap_int_t
rap_http_v2_data_frame_handler(rap_http_v2_connection_t *h2c,
    rap_http_v2_out_frame_t *frame)
{
    rap_buf_t             *buf;
    rap_chain_t           *cl, *ln;
    rap_http_v2_stream_t  *stream;

    stream = frame->stream;
    cl = frame->first;

    if (cl->buf->tag == (rap_buf_tag_t) &rap_http_v2_module) {

        if (cl->buf->pos != cl->buf->last) {
            rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui DATA frame %p was sent partially",
                           stream->node->id, frame);

            return RAP_AGAIN;
        }

        ln = cl->next;

        cl->next = stream->free_frame_headers;
        stream->free_frame_headers = cl;

        if (cl == frame->last) {
            goto done;
        }

        cl = ln;
    }

    for ( ;; ) {
        if (cl->buf->tag == (rap_buf_tag_t) &rap_http_v2_filter_get_shadow) {
            buf = cl->buf->shadow;

            if (rap_buf_in_memory(buf)) {
                buf->pos = cl->buf->pos;
            }

            if (buf->in_file) {
                buf->file_pos = cl->buf->file_pos;
            }
        }

        if (rap_buf_size(cl->buf) != 0) {

            if (cl != frame->first) {
                frame->first = cl;
                rap_http_v2_handle_stream(h2c, stream);
            }

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                           "http2:%ui DATA frame %p was sent partially",
                           stream->node->id, frame);

            return RAP_AGAIN;
        }

        ln = cl->next;

        if (cl->buf->tag == (rap_buf_tag_t) &rap_http_v2_filter_get_shadow) {
            cl->next = stream->free_bufs;
            stream->free_bufs = cl;

        } else {
            rap_free_chain(stream->request->pool, cl);
        }

        if (cl == frame->last) {
            goto done;
        }

        cl = ln;
    }

done:

    rap_log_debug2(RAP_LOG_DEBUG_HTTP, h2c->connection->log, 0,
                   "http2:%ui DATA frame %p was sent",
                   stream->node->id, frame);

    stream->request->header_size += RAP_HTTP_V2_FRAME_HEADER_SIZE;

    h2c->payload_bytes += frame->length;

    rap_http_v2_handle_frame(stream, frame);

    rap_http_v2_handle_stream(h2c, stream);

    return RAP_OK;
}


static rap_inline void
rap_http_v2_handle_frame(rap_http_v2_stream_t *stream,
    rap_http_v2_out_frame_t *frame)
{
    rap_http_request_t        *r;
    rap_http_v2_connection_t  *h2c;

    r = stream->request;

    r->connection->sent += RAP_HTTP_V2_FRAME_HEADER_SIZE + frame->length;

    h2c = stream->connection;

    h2c->total_bytes += RAP_HTTP_V2_FRAME_HEADER_SIZE + frame->length;

    if (frame->fin) {
        stream->out_closed = 1;
    }

    frame->next = stream->free_frames;
    stream->free_frames = frame;

    stream->queued--;
}


static rap_inline void
rap_http_v2_handle_stream(rap_http_v2_connection_t *h2c,
    rap_http_v2_stream_t *stream)
{
    rap_event_t       *wev;
    rap_connection_t  *fc;

    if (stream->waiting || stream->blocked) {
        return;
    }

    fc = stream->request->connection;

    if (!fc->error && stream->exhausted) {
        return;
    }

    wev = fc->write;

    wev->active = 0;
    wev->ready = 1;

    if (!fc->error && wev->delayed) {
        return;
    }

    rap_post_event(wev, &rap_posted_events);
}


static void
rap_http_v2_filter_cleanup(void *data)
{
    rap_http_v2_stream_t *stream = data;

    size_t                     window;
    rap_event_t               *wev;
    rap_queue_t               *q;
    rap_http_v2_out_frame_t   *frame, **fn;
    rap_http_v2_connection_t  *h2c;

    if (stream->waiting) {
        stream->waiting = 0;
        rap_queue_remove(&stream->queue);
    }

    if (stream->queued == 0) {
        return;
    }

    window = 0;
    h2c = stream->connection;
    fn = &h2c->last_out;

    for ( ;; ) {
        frame = *fn;

        if (frame == NULL) {
            break;
        }

        if (frame->stream == stream && !frame->blocked) {
            *fn = frame->next;

            window += frame->length;

            if (--stream->queued == 0) {
                break;
            }

            continue;
        }

        fn = &frame->next;
    }

    if (h2c->send_window == 0 && window) {

        while (!rap_queue_empty(&h2c->waiting)) {
            q = rap_queue_head(&h2c->waiting);

            rap_queue_remove(q);

            stream = rap_queue_data(q, rap_http_v2_stream_t, queue);

            stream->waiting = 0;

            wev = stream->request->connection->write;

            wev->active = 0;
            wev->ready = 1;

            if (!wev->delayed) {
                rap_post_event(wev, &rap_posted_events);
            }
        }
    }

    h2c->send_window += window;
}


static rap_int_t
rap_http_v2_filter_init(rap_conf_t *cf)
{
    rap_http_next_header_filter = rap_http_top_header_filter;
    rap_http_top_header_filter = rap_http_v2_header_filter;

    return RAP_OK;
}
