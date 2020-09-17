
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_http_upstream_conf_t   upstream;
    rp_int_t                  index;
    rp_uint_t                 gzip_flag;
} rp_http_memcached_loc_conf_t;


typedef struct {
    size_t                     rest;
    rp_http_request_t        *request;
    rp_str_t                  key;
} rp_http_memcached_ctx_t;


static rp_int_t rp_http_memcached_create_request(rp_http_request_t *r);
static rp_int_t rp_http_memcached_reinit_request(rp_http_request_t *r);
static rp_int_t rp_http_memcached_process_header(rp_http_request_t *r);
static rp_int_t rp_http_memcached_filter_init(void *data);
static rp_int_t rp_http_memcached_filter(void *data, ssize_t bytes);
static void rp_http_memcached_abort_request(rp_http_request_t *r);
static void rp_http_memcached_finalize_request(rp_http_request_t *r,
    rp_int_t rc);

static void *rp_http_memcached_create_loc_conf(rp_conf_t *cf);
static char *rp_http_memcached_merge_loc_conf(rp_conf_t *cf,
    void *parent, void *child);

static char *rp_http_memcached_pass(rp_conf_t *cf, rp_command_t *cmd,
    void *conf);


static rp_conf_bitmask_t  rp_http_memcached_next_upstream_masks[] = {
    { rp_string("error"), RP_HTTP_UPSTREAM_FT_ERROR },
    { rp_string("timeout"), RP_HTTP_UPSTREAM_FT_TIMEOUT },
    { rp_string("invalid_response"), RP_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { rp_string("not_found"), RP_HTTP_UPSTREAM_FT_HTTP_404 },
    { rp_string("off"), RP_HTTP_UPSTREAM_FT_OFF },
    { rp_null_string, 0 }
};


static rp_command_t  rp_http_memcached_commands[] = {

    { rp_string("memcached_pass"),
      RP_HTTP_LOC_CONF|RP_HTTP_LIF_CONF|RP_CONF_TAKE1,
      rp_http_memcached_pass,
      RP_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { rp_string("memcached_bind"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE12,
      rp_http_upstream_bind_set_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, upstream.local),
      NULL },

    { rp_string("memcached_socket_keepalive"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_FLAG,
      rp_conf_set_flag_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, upstream.socket_keepalive),
      NULL },

    { rp_string("memcached_connect_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, upstream.connect_timeout),
      NULL },

    { rp_string("memcached_send_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, upstream.send_timeout),
      NULL },

    { rp_string("memcached_buffer_size"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_size_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, upstream.buffer_size),
      NULL },

    { rp_string("memcached_read_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, upstream.read_timeout),
      NULL },

    { rp_string("memcached_next_upstream"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_1MORE,
      rp_conf_set_bitmask_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, upstream.next_upstream),
      &rp_http_memcached_next_upstream_masks },

    { rp_string("memcached_next_upstream_tries"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, upstream.next_upstream_tries),
      NULL },

    { rp_string("memcached_next_upstream_timeout"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_msec_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, upstream.next_upstream_timeout),
      NULL },

    { rp_string("memcached_gzip_flag"),
      RP_HTTP_MAIN_CONF|RP_HTTP_SRV_CONF|RP_HTTP_LOC_CONF|RP_CONF_TAKE1,
      rp_conf_set_num_slot,
      RP_HTTP_LOC_CONF_OFFSET,
      offsetof(rp_http_memcached_loc_conf_t, gzip_flag),
      NULL },

      rp_null_command
};


static rp_http_module_t  rp_http_memcached_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    rp_http_memcached_create_loc_conf,    /* create location configuration */
    rp_http_memcached_merge_loc_conf      /* merge location configuration */
};


rp_module_t  rp_http_memcached_module = {
    RP_MODULE_V1,
    &rp_http_memcached_module_ctx,        /* module context */
    rp_http_memcached_commands,           /* module directives */
    RP_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    RP_MODULE_V1_PADDING
};


static rp_str_t  rp_http_memcached_key = rp_string("memcached_key");


#define RP_HTTP_MEMCACHED_END   (sizeof(rp_http_memcached_end) - 1)
static u_char  rp_http_memcached_end[] = CRLF "END" CRLF;


static rp_int_t
rp_http_memcached_handler(rp_http_request_t *r)
{
    rp_int_t                       rc;
    rp_http_upstream_t            *u;
    rp_http_memcached_ctx_t       *ctx;
    rp_http_memcached_loc_conf_t  *mlcf;

    if (!(r->method & (RP_HTTP_GET|RP_HTTP_HEAD))) {
        return RP_HTTP_NOT_ALLOWED;
    }

    rc = rp_http_discard_request_body(r);

    if (rc != RP_OK) {
        return rc;
    }

    if (rp_http_set_content_type(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (rp_http_upstream_create(r) != RP_OK) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    u = r->upstream;

    rp_str_set(&u->schema, "memcached://");
    u->output.tag = (rp_buf_tag_t) &rp_http_memcached_module;

    mlcf = rp_http_get_module_loc_conf(r, rp_http_memcached_module);

    u->conf = &mlcf->upstream;

    u->create_request = rp_http_memcached_create_request;
    u->reinit_request = rp_http_memcached_reinit_request;
    u->process_header = rp_http_memcached_process_header;
    u->abort_request = rp_http_memcached_abort_request;
    u->finalize_request = rp_http_memcached_finalize_request;

    ctx = rp_palloc(r->pool, sizeof(rp_http_memcached_ctx_t));
    if (ctx == NULL) {
        return RP_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx->request = r;

    rp_http_set_ctx(r, ctx, rp_http_memcached_module);

    u->input_filter_init = rp_http_memcached_filter_init;
    u->input_filter = rp_http_memcached_filter;
    u->input_filter_ctx = ctx;

    r->main->count++;

    rp_http_upstream_init(r);

    return RP_DONE;
}


static rp_int_t
rp_http_memcached_create_request(rp_http_request_t *r)
{
    size_t                          len;
    uintptr_t                       escape;
    rp_buf_t                      *b;
    rp_chain_t                    *cl;
    rp_http_memcached_ctx_t       *ctx;
    rp_http_variable_value_t      *vv;
    rp_http_memcached_loc_conf_t  *mlcf;

    mlcf = rp_http_get_module_loc_conf(r, rp_http_memcached_module);

    vv = rp_http_get_indexed_variable(r, mlcf->index);

    if (vv == NULL || vv->not_found || vv->len == 0) {
        rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                      "the \"$memcached_key\" variable is not set");
        return RP_ERROR;
    }

    escape = 2 * rp_escape_uri(NULL, vv->data, vv->len, RP_ESCAPE_MEMCACHED);

    len = sizeof("get ") - 1 + vv->len + escape + sizeof(CRLF) - 1;

    b = rp_create_temp_buf(r->pool, len);
    if (b == NULL) {
        return RP_ERROR;
    }

    cl = rp_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return RP_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    *b->last++ = 'g'; *b->last++ = 'e'; *b->last++ = 't'; *b->last++ = ' ';

    ctx = rp_http_get_module_ctx(r, rp_http_memcached_module);

    ctx->key.data = b->last;

    if (escape == 0) {
        b->last = rp_copy(b->last, vv->data, vv->len);

    } else {
        b->last = (u_char *) rp_escape_uri(b->last, vv->data, vv->len,
                                            RP_ESCAPE_MEMCACHED);
    }

    ctx->key.len = b->last - ctx->key.data;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http memcached request: \"%V\"", &ctx->key);

    *b->last++ = CR; *b->last++ = LF;

    return RP_OK;
}


static rp_int_t
rp_http_memcached_reinit_request(rp_http_request_t *r)
{
    return RP_OK;
}


static rp_int_t
rp_http_memcached_process_header(rp_http_request_t *r)
{
    u_char                         *p, *start;
    rp_str_t                       line;
    rp_uint_t                      flags;
    rp_table_elt_t                *h;
    rp_http_upstream_t            *u;
    rp_http_memcached_ctx_t       *ctx;
    rp_http_memcached_loc_conf_t  *mlcf;

    u = r->upstream;

    for (p = u->buffer.pos; p < u->buffer.last; p++) {
        if (*p == LF) {
            goto found;
        }
    }

    return RP_AGAIN;

found:

    line.data = u->buffer.pos;
    line.len = p - u->buffer.pos;

    if (line.len == 0 || *(p - 1) != CR) {
        goto no_valid;
    }

    *p = '\0';
    line.len--;

    rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "memcached: \"%V\"", &line);

    p = u->buffer.pos;

    ctx = rp_http_get_module_ctx(r, rp_http_memcached_module);
    mlcf = rp_http_get_module_loc_conf(r, rp_http_memcached_module);

    if (rp_strncmp(p, "VALUE ", sizeof("VALUE ") - 1) == 0) {

        p += sizeof("VALUE ") - 1;

        if (rp_strncmp(p, ctx->key.data, ctx->key.len) != 0) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid key in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);

            return RP_HTTP_UPSTREAM_INVALID_HEADER;
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

        flags = rp_atoi(start, p - start - 1);

        if (flags == (rp_uint_t) RP_ERROR) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid flags in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return RP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        if (flags & mlcf->gzip_flag) {
            h = rp_list_push(&r->headers_out.headers);
            if (h == NULL) {
                return RP_ERROR;
            }

            h->hash = 1;
            rp_str_set(&h->key, "Content-Encoding");
            rp_str_set(&h->value, "gzip");
            r->headers_out.content_encoding = h;
        }

    length:

        start = p;
        p = line.data + line.len;

        u->headers_in.content_length_n = rp_atoof(start, p - start);
        if (u->headers_in.content_length_n == RP_ERROR) {
            rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                          "memcached sent invalid length in response \"%V\" "
                          "for key \"%V\"",
                          &line, &ctx->key);
            return RP_HTTP_UPSTREAM_INVALID_HEADER;
        }

        u->headers_in.status_n = 200;
        u->state->status = 200;
        u->buffer.pos = p + sizeof(CRLF) - 1;

        return RP_OK;
    }

    if (rp_strcmp(p, "END\x0d") == 0) {
        rp_log_error(RP_LOG_INFO, r->connection->log, 0,
                      "key: \"%V\" was not found by memcached", &ctx->key);

        u->headers_in.content_length_n = 0;
        u->headers_in.status_n = 404;
        u->state->status = 404;
        u->buffer.pos = p + sizeof("END" CRLF) - 1;
        u->keepalive = 1;

        return RP_OK;
    }

no_valid:

    rp_log_error(RP_LOG_ERR, r->connection->log, 0,
                  "memcached sent invalid response: \"%V\"", &line);

    return RP_HTTP_UPSTREAM_INVALID_HEADER;
}


static rp_int_t
rp_http_memcached_filter_init(void *data)
{
    rp_http_memcached_ctx_t  *ctx = data;

    rp_http_upstream_t  *u;

    u = ctx->request->upstream;

    if (u->headers_in.status_n != 404) {
        u->length = u->headers_in.content_length_n + RP_HTTP_MEMCACHED_END;
        ctx->rest = RP_HTTP_MEMCACHED_END;

    } else {
        u->length = 0;
    }

    return RP_OK;
}


static rp_int_t
rp_http_memcached_filter(void *data, ssize_t bytes)
{
    rp_http_memcached_ctx_t  *ctx = data;

    u_char               *last;
    rp_buf_t            *b;
    rp_chain_t          *cl, **ll;
    rp_http_upstream_t  *u;

    u = ctx->request->upstream;
    b = &u->buffer;

    if (u->length == (ssize_t) ctx->rest) {

        if (rp_strncmp(b->last,
                   rp_http_memcached_end + RP_HTTP_MEMCACHED_END - ctx->rest,
                   bytes)
            != 0)
        {
            rp_log_error(RP_LOG_ERR, ctx->request->connection->log, 0,
                          "memcached sent invalid trailer");

            u->length = 0;
            ctx->rest = 0;

            return RP_OK;
        }

        u->length -= bytes;
        ctx->rest -= bytes;

        if (u->length == 0) {
            u->keepalive = 1;
        }

        return RP_OK;
    }

    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
        ll = &cl->next;
    }

    cl = rp_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
    if (cl == NULL) {
        return RP_ERROR;
    }

    cl->buf->flush = 1;
    cl->buf->memory = 1;

    *ll = cl;

    last = b->last;
    cl->buf->pos = last;
    b->last += bytes;
    cl->buf->last = b->last;
    cl->buf->tag = u->output.tag;

    rp_log_debug4(RP_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "memcached filter bytes:%z size:%z length:%O rest:%z",
                   bytes, b->last - b->pos, u->length, ctx->rest);

    if (bytes <= (ssize_t) (u->length - RP_HTTP_MEMCACHED_END)) {
        u->length -= bytes;
        return RP_OK;
    }

    last += (size_t) (u->length - RP_HTTP_MEMCACHED_END);

    if (rp_strncmp(last, rp_http_memcached_end, b->last - last) != 0) {
        rp_log_error(RP_LOG_ERR, ctx->request->connection->log, 0,
                      "memcached sent invalid trailer");

        b->last = last;
        cl->buf->last = last;
        u->length = 0;
        ctx->rest = 0;

        return RP_OK;
    }

    ctx->rest -= b->last - last;
    b->last = last;
    cl->buf->last = last;
    u->length = ctx->rest;

    if (u->length == 0) {
        u->keepalive = 1;
    }

    return RP_OK;
}


static void
rp_http_memcached_abort_request(rp_http_request_t *r)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http memcached request");
    return;
}


static void
rp_http_memcached_finalize_request(rp_http_request_t *r, rp_int_t rc)
{
    rp_log_debug0(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http memcached request");
    return;
}


static void *
rp_http_memcached_create_loc_conf(rp_conf_t *cf)
{
    rp_http_memcached_loc_conf_t  *conf;

    conf = rp_pcalloc(cf->pool, sizeof(rp_http_memcached_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by rp_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     */

    conf->upstream.local = RP_CONF_UNSET_PTR;
    conf->upstream.socket_keepalive = RP_CONF_UNSET;
    conf->upstream.next_upstream_tries = RP_CONF_UNSET_UINT;
    conf->upstream.connect_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = RP_CONF_UNSET_MSEC;
    conf->upstream.next_upstream_timeout = RP_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = RP_CONF_UNSET_SIZE;

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

    conf->index = RP_CONF_UNSET;
    conf->gzip_flag = RP_CONF_UNSET_UINT;

    return conf;
}


static char *
rp_http_memcached_merge_loc_conf(rp_conf_t *cf, void *parent, void *child)
{
    rp_http_memcached_loc_conf_t *prev = parent;
    rp_http_memcached_loc_conf_t *conf = child;

    rp_conf_merge_ptr_value(conf->upstream.local,
                              prev->upstream.local, NULL);

    rp_conf_merge_value(conf->upstream.socket_keepalive,
                              prev->upstream.socket_keepalive, 0);

    rp_conf_merge_uint_value(conf->upstream.next_upstream_tries,
                              prev->upstream.next_upstream_tries, 0);

    rp_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    rp_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    rp_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    rp_conf_merge_msec_value(conf->upstream.next_upstream_timeout,
                              prev->upstream.next_upstream_timeout, 0);

    rp_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) rp_pagesize);

    rp_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (RP_CONF_BITMASK_SET
                               |RP_HTTP_UPSTREAM_FT_ERROR
                               |RP_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & RP_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = RP_CONF_BITMASK_SET
                                       |RP_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->index == RP_CONF_UNSET) {
        conf->index = prev->index;
    }

    rp_conf_merge_uint_value(conf->gzip_flag, prev->gzip_flag, 0);

    return RP_CONF_OK;
}


static char *
rp_http_memcached_pass(rp_conf_t *cf, rp_command_t *cmd, void *conf)
{
    rp_http_memcached_loc_conf_t *mlcf = conf;

    rp_str_t                 *value;
    rp_url_t                  u;
    rp_http_core_loc_conf_t  *clcf;

    if (mlcf->upstream.upstream) {
        return "is duplicate";
    }

    value = cf->args->elts;

    rp_memzero(&u, sizeof(rp_url_t));

    u.url = value[1];
    u.no_resolve = 1;

    mlcf->upstream.upstream = rp_http_upstream_add(cf, &u, 0);
    if (mlcf->upstream.upstream == NULL) {
        return RP_CONF_ERROR;
    }

    clcf = rp_http_conf_get_module_loc_conf(cf, rp_http_core_module);

    clcf->handler = rp_http_memcached_handler;

    if (clcf->name.len && clcf->name.data[clcf->name.len - 1] == '/') {
        clcf->auto_redirect = 1;
    }

    mlcf->index = rp_http_get_variable_index(cf, &rp_http_memcached_key);

    if (mlcf->index == RP_ERROR) {
        return RP_CONF_ERROR;
    }

    return RP_CONF_OK;
}
