
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static rp_int_t rp_http_postpone_filter_add(rp_http_request_t *r,
    rp_chain_t *in);
static rp_int_t rp_http_postpone_filter_in_memory(rp_http_request_t *r,
    rp_chain_t *in);
static rp_int_t rp_http_postpone_filter_init(rp_conf_t *cf);


static rp_http_module_t  rp_http_postpone_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_postpone_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rp_module_t  rp_http_postpone_filter_module = {
    RP_MODULE_V1,
    &rp_http_postpone_filter_module_ctx,  /* module context */
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


static rp_http_output_body_filter_pt    rp_http_next_body_filter;


static rp_int_t
rp_http_postpone_filter(rp_http_request_t *r, rp_chain_t *in)
{
    rp_connection_t              *c;
    rp_http_postponed_request_t  *pr;

    c = r->connection;

    rp_log_debug3(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter \"%V?%V\" %p", &r->uri, &r->args, in);

    if (r->subrequest_in_memory) {
        return rp_http_postpone_filter_in_memory(r, in);
    }

    if (r != c->data) {

        if (in) {
            if (rp_http_postpone_filter_add(r, in) != RP_OK) {
                return RP_ERROR;
            }

            return RP_OK;
        }

#if 0
        /* TODO: SSI may pass NULL */
        rp_log_error(RP_LOG_ALERT, c->log, 0,
                      "http postpone filter NULL inactive request");
#endif

        return RP_OK;
    }

    if (r->postponed == NULL) {

        if (in || c->buffered) {
            return rp_http_next_body_filter(r->main, in);
        }

        return RP_OK;
    }

    if (in) {
        if (rp_http_postpone_filter_add(r, in) != RP_OK) {
            return RP_ERROR;
        }
    }

    do {
        pr = r->postponed;

        if (pr->request) {

            rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter wake \"%V?%V\"",
                           &pr->request->uri, &pr->request->args);

            r->postponed = pr->next;

            c->data = pr->request;

            return rp_http_post_request(pr->request, NULL);
        }

        if (pr->out == NULL) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
                          "http postpone filter NULL output");

        } else {
            rp_log_debug2(RP_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter output \"%V?%V\"",
                           &r->uri, &r->args);

            if (rp_http_next_body_filter(r->main, pr->out) == RP_ERROR) {
                return RP_ERROR;
            }
        }

        r->postponed = pr->next;

    } while (r->postponed);

    return RP_OK;
}


static rp_int_t
rp_http_postpone_filter_add(rp_http_request_t *r, rp_chain_t *in)
{
    rp_http_postponed_request_t  *pr, **ppr;

    if (r->postponed) {
        for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }

        if (pr->request == NULL) {
            goto found;
        }

        ppr = &pr->next;

    } else {
        ppr = &r->postponed;
    }

    pr = rp_palloc(r->pool, sizeof(rp_http_postponed_request_t));
    if (pr == NULL) {
        return RP_ERROR;
    }

    *ppr = pr;

    pr->request = NULL;
    pr->out = NULL;
    pr->next = NULL;

found:

    if (rp_chain_add_copy(r->pool, &pr->out, in) == RP_OK) {
        return RP_OK;
    }

    return RP_ERROR;
}


static rp_int_t
rp_http_postpone_filter_in_memory(rp_http_request_t *r, rp_chain_t *in)
{
    size_t                     len;
    rp_buf_t                 *b;
    rp_connection_t          *c;
    rp_http_core_loc_conf_t  *clcf;

    c = r->connection;

    rp_log_debug0(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter in memory");

    if (r->out == NULL) {
        clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

        if (r->headers_out.content_length_n != -1) {
            len = r->headers_out.content_length_n;

            if (len > clcf->subrequest_output_buffer_size) {
                rp_log_error(RP_LOG_ERR, c->log, 0,
                              "too big subrequest response: %uz", len);
                return RP_ERROR;
            }

        } else {
            len = clcf->subrequest_output_buffer_size;
        }

        b = rp_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return RP_ERROR;
        }

        b->last_buf = 1;

        r->out = rp_alloc_chain_link(r->pool);
        if (r->out == NULL) {
            return RP_ERROR;
        }

        r->out->buf = b;
        r->out->next = NULL;
    }

    b = r->out->buf;

    for ( /* void */ ; in; in = in->next) {

        if (rp_buf_special(in->buf)) {
            continue;
        }

        len = in->buf->last - in->buf->pos;

        if (len > (size_t) (b->end - b->last)) {
            rp_log_error(RP_LOG_ERR, c->log, 0,
                          "too big subrequest response");
            return RP_ERROR;
        }

        rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                       "http postpone filter in memory %uz bytes", len);

        b->last = rp_cpymem(b->last, in->buf->pos, len);
        in->buf->pos = in->buf->last;
    }

    return RP_OK;
}


static rp_int_t
rp_http_postpone_filter_init(rp_conf_t *cf)
{
    rp_http_next_body_filter = rp_http_top_body_filter;
    rp_http_top_body_filter = rp_http_postpone_filter;

    return RP_OK;
}
