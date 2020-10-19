
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


typedef struct {
    rap_http_upstream_conf_t   upstream;
    rap_int_t                  index;
    rap_uint_t                 gzip_flag;
} rap_http_memcached_loc_conf_t;


typedef struct {
    size_t                     rest;
    rap_http_request_t        *request;
    rap_str_t                  key;
} rap_http_memcached_ctx_t;


static rap_int_t rap_http_memcached_create_request(rap_http_request_t *r);
static rap_int_t rap_http_memcached_reinit_request(rap_http_request_t *r);
static rap_int_t rap_http_memcached_process_header(rap_http_request_t *r);
static rap_int_t rap_http_memcached_filter_init(void *data);
static rap_int_t rap_http_memcached_filter(void *data, ssize_t bytes);
static void rap_http_memcached_abort_request(rap_http_request_t *r);
static void rap_http_memcached_finalize_request(rap_http_request_t *r,
    rap_int_t rc);

static void *rap_http_memcached_create_loc_conf(rap_conf_t *cf);
static char *rap_http_memcached_merge_loc_conf(rap_conf_t *cf,
    void *parent, void *child);

static char *rap_http_memcached_pass(rap_conf_t *cf, rap_command_t *cmd,
    void *conf);


static rap_conf_bitmask_t  rap_http_memcached_next_upstream_masks[] = {
    { rap_string("error"), RAP_HTTP_UPSTREAM_FT_ERROR },
    { rap_string("timeout"), RAP_HTTP_UPSTREAM_FT_TIMEOUT },
    { rap_string("invalid_response"), RAP_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { rap_string("not_found"), RAP_HTTP_UPSTREAM_FT_HTTP_404 },
    { rap_string("off"), RAP_HTTP_UPSTREAM_FT_OFF },
    { rap_null_string, 0 }
};


static rap_command_t  rap_http_memcached_commands[] = {

    { rap_string("memcached_pass"),
      RAP_HTTP_LOC_CONF|RAP_HTTP_LIF_CONF|RAP_CONF_TAKE1,
      rap_http_memcached_pass,
      RAP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rap_string("memcached_bind"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE12,
      rap_http_upstream_bind_set_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, upstream.local),
      NULL },

    { rap_string("memcached_socket_keepalive"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_FLAG,
      rap_conf_set_flag_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { rap_string("memcached_connect_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, upstream.connect_timeout),
      NULL },

    { rap_string("memcached_send_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, upstream.send_timeout),
      NULL },

    { rap_string("memcached_buffer_size"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_size_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, upstream.buffer_size),
      NULL },

    { rap_string("memcached_read_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, upstream.read_timeout),
      NULL },

    { rap_string("memcached_next_upstream"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_1MORE,
      rap_conf_set_bitmask_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, upstream.next_upstream),
      &rap_http_memcached_next_upstream_masks },

    { rap_string("memcached_next_upstream_tries"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { rap_string("memcached_next_upstream_timeout"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_msec_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { rap_string("memcached_gzip_flag"),
      RAP_HTTP_MAIN_CONF|RAP_HTTP_SRV_CONF|RAP_HTTP_LOC_CONF|RAP_CONF_TAKE1,
      rap_conf_set_num_slot,
      RAP_HTTP_LOC_CONF_OFFSET,
      offsetof(rap_http_memcached_loc_conf_t, gzip_flag),
      NULL },

      rap_null_command
};


static rap_http_module_t  rap_http_memcached_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rap_http_memcached_create_loc_conf,    /* create location configuration */
    rap_http_memcached_merge_loc_conf      /* merge location configuration */
};


rap_module_t  rap_http_memcached_module = {
    RAP_MODULE_V1,
    &rap_http_memcached_module_ctx,        /* module context */
    rap_http_memcached_commands,           /* module directives */
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


static rap_str_t  rap_http_memcached_key = rap_string("memcached_key");


#define RAP_HTTP_MEMCACHED_END   (sizeof(rap_http_memcached_end) - 1)
static u_char  rap_http_memcached_end[] = CRLF "END" CRLF;


static rap_int_t
rap_http_memcached_handler(rap_http_request_t *r)
{
    rap_int_t                       rc;
    rap_http_upstream_t            *u;
    rap_http_memcached_ctx_t       *ctx;
    rap_http_memcached_loc_conf_t  *mlcf;

    if (!(r->method & (RAP_HTTP_GET|RAP_HTTP_HEAD))) {
        return RAP_HTTP_NOT_ALLOWED;
    }

    rc = rap_http_discard_request_body(r);

    if (rc != RAP_OK) {
        return rc;
    }

    if (rap_http_set_content_type(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rap_http_upstream_create(r) != RAP_OK) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    rap_str_set(&u->schema, "memcached://");
    u->output.tag = (rap_buf_tag_t) &rap_http_memcached_module;

    mlcf = rap_http_get_module_loc_conf(r, rap_http_memcached_module);

    u->conf = &mlcf->upstream;

    u->create_request = rap_http_memcached_create_request;
    u->reinit_request = rap_http_memcached_reinit_request;
    u->process_header = rap_http_memcached_process_header;
    u->abort_request = rap_http_memcached_abort_request;
    u->finalize_request = rap_http_memcached_finalize_request;

    ctx = rap_palloc(r->pool, sizeof(rap_http_memcached_ctx_t));
    if (ctx == NULL) {
        return RAP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    rap_http_set_ctx(r, ctx, rap_http_memcached_module);

    u->input_filter_init = rap_http_memcached_filter_init;
    u->input_filter = rap_http_memcached_filter;
    u->input_filter_ctx = ctx;

    r->main->count++;

    rap_http_upstream_init(r);

    return RAP_DONE;
}


static rap_int_t
rap_http_memcached_create_request(rap_http_request_t *r)
{
    size_t                          len;
    uintptr_t                       escape;
    rap_buf_t                      *b;
    rap_chain_t                    *cl;
    rap_http_memcached_ctx_t       *ctx;
    rap_http_variable_value_t      *vv;
    rap_http_memcached_loc_conf_t  *mlcf;

    mlcf = rap_http_get_module_loc_conf(r, rap_http_memcached_module);

    vv = rap_http_get_indexed_variable(r, mlcf->index);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                      "the \"$memcached_key\" variable is not set");
        return RAP_ERROR;
    }

    escape = 2 * rap_escape_uri(NULL, vv->data, vv->len, RAP_ESCAPE_MEMCACHED);

    len = sizeof("get ") - 1 + vv->len + escape + sizeof(CRLF) - 1;

    b = rap_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return RAP_ERROR;
    }

    cl = rap_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    *b->last++ = 'g'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';

    ctx = rap_http_get_module_ctx(r, rap_http_memcached_module);

    ctx->key.data = b->last;

    if (escape == 0) {
        b->last = rap_copy(b->last, vv->data, vv->len);

    } else {
        b->last = (u_char *) rap_escape_uri(b->last, vv->data, vv->len,
                                            RAP_ESCAPE_MEMCACHED);
    }

    ctx->key.len = b->last - ctx->key.data;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http memcached request: \"%V\"", &ctx->key);

    *b->last++ = CR; *b->last++ = LF;

    return RAP_OK;
}


static rap_int_t
rap_http_memcached_reinit_request(rap_http_request_t *r)
{
    return RAP_OK;
}


static rap_int_t
rap_http_memcached_process_header(rap_http_request_t *r)
{
    u_char                         *p, *start;
    rap_str_t                       line;
    rap_uint_t                      flags;
    rap_table_elt_t                *h;
    rap_http_upstream_t            *u;
    rap_http_memcached_ctx_t       *ctx;
    rap_http_memcached_loc_conf_t  *mlcf;

    u = r->upstream;

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    return RAP_AGAIN;

found:

    line.data = u->buffer.pos;
    line.len = p - u->buffer.pos;

    if (line.len == 0 || *(p - 1) != CR) {
        goto no_valid;
    }

    *p = '\0';
    line.len--;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "memcached: \"%V\"", &line);

    p = u->buffer.pos;

    ctx = rap_http_get_module_ctx(r, rap_http_memcached_module);
    mlcf = rap_http_get_module_loc_conf(r, rap_http_memcached_module);

    if (rap_strncmp(p, "VALUE ", sizeof("VALUE ") - 1) == 0) {

        p += sizeof("VALUE ") - 1;

        if (rap_strncmp(p, ctx->key.data, ctx->key.len) != 0) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid key in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);

            return RAP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        p += ctx->key.len;

        if (*p++ != ' ') {
            goto no_valid;
        }

        /* flags */

        start = p;

        while (*p) {
            if (*p++ == ' ') {
                if (mlcf->gzip_flag) {
                    goto flags;
                } else {
                    goto length;
                }
            }
        }

        goto no_valid;

    flags:

        flags = rap_atoi(start, p - start - 1);

        if (flags == (rap_uint_t) RAP_ERROR) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid flags in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return RAP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (flags & mlcf->gzip_flag) {
            h = rap_list_push(&r->headers_out.headers);
            if (h == NULL) {
                return RAP_ERROR;
            }

            h->hash = 1;
            rap_str_set(&h->key, "Content-Encoding");
            rap_str_set(&h->value, "gzip");
            r->headers_out.content_encoding = h;
        }

    length:

        start = p;
        p = line.data + line.len;

        u->headers_in.content_length_n = rap_atoof(start, p - start);
        if (u->headers_in.content_length_n == RAP_ERROR) {
            rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid length in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return RAP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        u->headers_in.status_n = 200;
        u->state->status = 200;
        u->buffer.pos = p + sizeof(CRLF) - 1;

        return RAP_OK;
    }

    if (rap_strcmp(p, "END\x0d") == 0) {
        rap_log_error(RAP_LOG_INFO, r->connection->log, 0,
                      "key: \"%V\" was not found by memcached", &ctx->key);

        u->headers_in.content_length_n = 0;
        u->headers_in.status_n = 404;
        u->state->status = 404;
        u->buffer.pos = p + sizeof("END" CRLF) - 1;
        u->keepalive = 1;

        return RAP_OK;
    }

no_valid:

    rap_log_error(RAP_LOG_ERR, r->connection->log, 0,
                  "memcached sent invalid response: \"%V\"", &line);

    return RAP_HTTP_UPSTREAM_INVALID_HEADER;
}


static rap_int_t
rap_http_memcached_filter_init(void *data)
{
    rap_http_memcached_ctx_t  *ctx = data;

    rap_http_upstream_t  *u;

    u = ctx->request->upstream;

    if (u->headers_in.status_n != 404) {
        u->length = u->headers_in.content_length_n + RAP_HTTP_MEMCACHED_END;
        ctx->rest = RAP_HTTP_MEMCACHED_END;

    } else {
        u->length = 0;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_memcached_filter(void *data, ssize_t bytes)
{
    rap_http_memcached_ctx_t  *ctx = data;

    u_char               *last;
    rap_buf_t            *b;
    rap_chain_t          *cl, **ll;
    rap_http_upstream_t  *u;

    u = ctx->request->upstream;
    b = &u->buffer;

    if (u->length == (ssize_t) ctx->rest) {

        if (rap_strncmp(b->last,
                   rap_http_memcached_end + RAP_HTTP_MEMCACHED_END - ctx->rest,
                   bytes)
            != 0)
        {
            rap_log_error(RAP_LOG_ERR, ctx->request->connection->log, 0,
                          "memcached sent invalid trailer");

            u->length = 0;
            ctx->rest = 0;

            return RAP_OK;
        }

        u->length -= bytes;
        ctx->rest -= bytes;

        if (u->length == 0) {
            u->keepalive = 1;
        }

        return RAP_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rap_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    last = b->last;
    cl->buf->pos = last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    rap_log_debug4(RAP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "memcached filter bytes:%z size:%z length:%O rest:%z",
                   bytes, b->last - b->pos, u->length, ctx->rest);

    if (bytes <= (ssize_t) (u->length - RAP_HTTP_MEMCACHED_END)) {
        u->length -= bytes;
        return RAP_OK;
    }

    last += (size_t) (u->length - RAP_HTTP_MEMCACHED_END);

    if (rap_strncmp(last, rap_http_memcached_end, b->last - last) != 0) {
        rap_log_error(RAP_LOG_ERR, ctx->request->connection->log, 0,
                      "memcached sent invalid trailer");

        b->last = last;
        cl->buf->last = last;
        u->length = 0;
        ctx->rest = 0;

        return RAP_OK;
    }

    ctx->rest -= b->last - last;
    b->last = last;
    cl->buf->last = last;
    u->length = ctx->rest;

    if (u->length == 0) {
        u->keepalive = 1;
    }

    return RAP_OK;
}


static void
rap_http_memcached_abort_request(rap_http_request_t *r)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http memcached request");
    return;
}


static void
rap_http_memcached_finalize_request(rap_http_request_t *r, rap_int_t rc)
{
    rap_log_debug0(RAP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http memcached request");
    return;
}


static void *
rap_http_memcached_create_loc_conf(rap_conf_t *cf)
{
    rap_http_memcached_loc_conf_t  *conf;

    conf = rap_pcalloc(cf->pool, sizeof(rap_http_memcached_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rap_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     */

    conf->upstream.local = RAP_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = RAP_CONF_UNSET;
    conf->upstream.next_upstream_tries = RAP_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = RAP_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = RAP_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = RAP_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;
    conf->upstream.force_ranges = 1;

    conf->index = RAP_CONF_UNSET;
    conf->gzip_flag = RAP_CONF_UNSET_UINT;

    return conf;
}


static char *
rap_http_memcached_merge_loc_conf(rap_conf_t *cf, void *parent, void *child)
{
    rap_http_memcached_loc_conf_t *prev = parent;
    rap_http_memcached_loc_conf_t *conf = child;

    rap_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    rap_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    rap_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    rap_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    rap_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    rap_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) rap_pagesize);

    rap_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (RAP_CONF_BITMASK_SET
                               |RAP_HTTP_UPSTREAM_FT_ERROR
                               |RAP_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & RAP_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = RAP_CONF_BITMASK_SET
                                       |RAP_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->index == RAP_CONF_UNSET) {
        conf->index = prev->index;
    }

    rap_conf_merge_uint_value(conf->gzip_flag, prev->gzip_flag, 0);

    return RAP_CONF_OK;
}


static char *
rap_http_memcached_pass(rap_conf_t *cf, rap_command_t *cmd, void *conf)
{
    rap_http_memcached_loc_conf_t *mlcf = conf;

    rap_str_t                 *value;
    rap_url_t                  u;
    rap_http_core_loc_conf_t  *clcf;

    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    rap_memzero(&u, sizeof(rap_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    mlcf->upstream.upstream = rap_http_upstream_add(cf, &u, 0);
    if (mlcf->upstream.upstream == NULL) {
        return RAP_CONF_ERROR;
    }

    clcf = rap_http_conf_get_module_loc_conf(cf, rap_http_core_module);

    clcf->handler = rap_http_memcached_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    mlcf->index = rap_http_get_variable_index(cf, &rap_http_memcached_key);

    if (mlcf->index == RAP_ERROR) {
        return RAP_CONF_ERROR;
    }

    return RAP_CONF_OK;
}
