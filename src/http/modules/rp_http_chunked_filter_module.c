
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


typedef struct {
    rp_chain_t         *free;
    rp_chain_t         *busy;
} rp_http_chunked_filter_ctx_t;


static rp_int_t rp_http_chunked_filter_init(rp_conf_t *cf);
static rp_chain_t *rp_http_chunked_create_trailers(rp_http_request_t *r,
    rp_http_chunked_filter_ctx_t *ctx);


static rp_http_module_t  rp_http_chunked_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_chunked_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_chunked_filter_module = {
    RP_MODULE_V1,
    &rp_http_chunked_filter_module_ctx,   /* module context */
    NULL,                                  /* module directives */
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


static rp_http_output_header_filter_pt  rp_http_next_header_filter;
static rp_http_output_body_filter_pt    rp_http_next_body_filter;


static rp_int_t
rp_http_chunked_header_filter(rp_http_request_t *r)
{
    rp_http_core_loc_conf_t       *clcf;
    rp_http_chunked_filter_ctx_t  *ctx;

    if (r->headers_out.status == RP_HTTP_NOT_MODIFIED
        || r->headers_out.status == RP_HTTP_NO_CONTENT
        || r->headers_out.status < RP_HTTP_OK
        || r != r->main
        || r->method == RP_HTTP_HEAD)
    {
        return rp_http_next_header_filter(r);
    }

    if (r->headers_out.content_length_n == -1
        || r->expect_trailers)
    {
        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

        if (r->http_version >= RP_HTTP_VERSION_11
            && clcf->chunked_transfer_encoding)
        {
            if (r->expect_trailers) {
                rp_http_clear_content_length(r);
            }

            r->chunked = 1;

            ctx = rp_pcalloc(r->pool, sizeof(rp_http_chunked_filter_ctx_t));
            if (ctx == NULL) {
                return RP_ERROR;
            }

            rp_http_set_ctx(r, ctx, rp_http_chunked_filter_module);

        } else if (r->headers_out.content_length_n == -1) {
            r->keepalive = 0;
        }
    }

    return rp_http_next_header_filter(r);
}


static rp_int_t
rp_http_chunked_body_filter(rp_http_request_t *r, rp_chain_t *in)
{
    u_char                         *chunk;
    off_t                           size;
    rp_int_t                       rc;
    rp_buf_t                      *b;
    rp_chain_t                    *out, *cl, *tl, **ll;
    rp_http_chunked_filter_ctx_t  *ctx;

    if (in == NULL || !r->chunked || r->header_only) {
        return rp_http_next_body_filter(r, in);
    }

    ctx = rp_http_get_module_ctx(r, rp_http_chunked_filter_module);

    out = NULL;
    ll = &out;

    size = 0;
    cl = in;

    for ( ;; ) {
        rp_log_debug1(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http chunk: %O", rp_buf_size(cl->buf));

        size += rp_buf_size(cl->buf);

        if (cl->buf->flush
            || cl->buf->sync
            || rp_buf_in_memory(cl->buf)
            || cl->buf->in_file)
        {
            tl = rp_alloc_chain_link(r->pool);
            if (tl == NULL) {
                return RP_ERROR;
            }

            tl->buf = cl->buf;
            *ll = tl;
            ll = &tl->next;
        }

        if (cl->next == NULL) {
            break;
        }

        cl = cl->next;
    }

    if (size) {
        tl = rp_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return RP_ERROR;
        }

        b = tl->buf;
        chunk = b->start;

        if (chunk == NULL) {
            /* the "0000000000000000" is 64-bit hexadecimal string */

            chunk = rp_palloc(r->pool, sizeof("0000000000000000" CRLF) - 1);
            if (chunk == NULL) {
                return RP_ERROR;
            }

            b->start = chunk;
            b->end = chunk + sizeof("0000000000000000" CRLF) - 1;
        }

        b->tag = (rp_buf_tag_t) &rp_http_chunked_filter_module;
        b->memory = 0;
        b->temporary = 1;
        b->pos = chunk;
        b->last = rp_sprintf(chunk, "%xO" CRLF, size);

        tl->next = out;
        out = tl;
    }

    if (cl->buf->last_buf) {
        tl = rp_http_chunked_create_trailers(r, ctx);
        if (tl == NULL) {
            return RP_ERROR;
        }

        cl->buf->last_buf = 0;

        *ll = tl;

        if (size == 0) {
            tl->buf->pos += 2;
        }

    } else if (size > 0) {
        tl = rp_chain_get_free_buf(r->pool, &ctx->free);
        if (tl == NULL) {
            return RP_ERROR;
        }

        b = tl->buf;

        b->tag = (rp_buf_tag_t) &rp_http_chunked_filter_module;
        b->temporary = 0;
        b->memory = 1;
        b->pos = (u_char *) CRLF;
        b->last = b->pos + 2;

        *ll = tl;

    } else {
        *ll = NULL;
    }

    rc = rp_http_next_body_filter(r, out);

    rp_chain_update_chains(r->pool, &ctx->free, &ctx->busy, &out,
                            (rp_buf_tag_t) &rp_http_chunked_filter_module);

    return rc;
}


static rp_chain_t *
rp_http_chunked_create_trailers(rp_http_request_t *r,
    rp_http_chunked_filter_ctx_t *ctx)
{
    size_t            len;
    rp_buf_t        *b;
    rp_uint_t        i;
    rp_chain_t      *cl;
    rp_list_part_t  *part;
    rp_table_elt_t  *header;

    len = 0;

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

        len += header[i].key.len + sizeof(": ") - 1
               + header[i].value.len + sizeof(CRLF) - 1;
    }

    cl = rp_chain_get_free_buf(r->pool, &ctx->free);
    if (cl == NULL) {
        return NULL;
    }

    b = cl->buf;

    b->tag = (rp_buf_tag_t) &rp_http_chunked_filter_module;
    b->temporary = 0;
    b->memory = 1;
    b->last_buf = 1;

    if (len == 0) {
        b->pos = (u_char *) CRLF "0" CRLF CRLF;
        b->last = b->pos + sizeof(CRLF "0" CRLF CRLF) - 1;
        return cl;
    }

    len += sizeof(CRLF "0" CRLF CRLF) - 1;

    b->pos = rp_palloc(r->pool, len);
    if (b->pos == NULL) {
        return NULL;
    }

    b->last = b->pos;

    *b->last++ = CR; *b->last++ = LF;
    *b->last++ = '0';
    *b->last++ = CR; *b->last++ = LF;

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

        rp_log_debug2(RP_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http trailer: \"%V: %V\"",
                       &header[i].key, &header[i].value);

        b->last = rp_copy(b->last, header[i].key.data, header[i].key.len);
        *b->last++ = ':'; *b->last++ = ' ';

        b->last = rp_copy(b->last, header[i].value.data, header[i].value.len);
        *b->last++ = CR; *b->last++ = LF;
    }

    *b->last++ = CR; *b->last++ = LF;

    return cl;
}


static rp_int_t
rp_http_chunked_filter_init(rp_conf_t *cf)
{
    rp_http_next_header_filter = rp_http_top_header_filter;
    rp_http_top_header_filter = rp_http_chunked_header_filter;

    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_chunked_body_filter;

    return RP_OK;
}
