
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static rap_int_t rap_http_postpone_filter_add(rap_http_request_t *r,
    rap_chain_t *in);
static rap_int_t rap_http_postpone_filter_in_memory(rap_http_request_t *r,
    rap_chain_t *in);
static rap_int_t rap_http_postpone_filter_init(rap_conf_t *cf);


static rap_http_module_t  rap_http_postpone_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_postpone_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


rap_module_t  rap_http_postpone_filter_module = {
    RAP_MODULE_V1,
    &rap_http_postpone_filter_module_ctx,  /* module context */
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


static rap_http_output_body_filter_pt    rap_http_next_body_filter;


static rap_int_t
rap_http_postpone_filter(rap_http_request_t *r, rap_chain_t *in)
{
    rap_connection_t              *c;
    rap_http_postponed_request_t  *pr;

    c = r->connection;

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter \"%V?%V\" %p", &r->uri, &r->args, in);

    if (r->subrequest_in_memory) {
        return rap_http_postpone_filter_in_memory(r, in);
    }

    if (r != c->data) {

        if (in) {
            if (rap_http_postpone_filter_add(r, in) != RAP_OK) {
                return RAP_ERROR;
            }

            return RAP_OK;
        }

#if 0
        /* TODO: SSI may pass NULL */
        rap_log_error(RAP_LOG_ALERT, c->log, 0,
                      "http postpone filter NULL inactive request");
#endif

        return RAP_OK;
    }

    if (r->postponed == NULL) {

        if (in || c->buffered) {
            return rap_http_next_body_filter(r->main, in);
        }

        return RAP_OK;
    }

    if (in) {
        if (rap_http_postpone_filter_add(r, in) != RAP_OK) {
            return RAP_ERROR;
        }
    }

    do {
        pr = r->postponed;

        if (pr->request) {

            rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter wake \"%V?%V\"",
                           &pr->request->uri, &pr->request->args);

            r->postponed = pr->next;

            c->data = pr->request;

            return rap_http_post_request(pr->request, NULL);
        }

        if (pr->out == NULL) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
                          "http postpone filter NULL output");

        } else {
            rap_log_debug2(RAP_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter output \"%V?%V\"",
                           &r->uri, &r->args);

            if (rap_http_next_body_filter(r->main, pr->out) == RAP_ERROR) {
                return RAP_ERROR;
            }
        }

        r->postponed = pr->next;

    } while (r->postponed);

    return RAP_OK;
}


static rap_int_t
rap_http_postpone_filter_add(rap_http_request_t *r, rap_chain_t *in)
{
    rap_http_postponed_request_t  *pr, **ppr;

    if (r->postponed) {
        for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }

        if (pr->request == NULL) {
            goto found;
        }

        ppr = &pr->next;

    } else {
        ppr = &r->postponed;
    }

    pr = rap_palloc(r->pool, sizeof(rap_http_postponed_request_t));
    if (pr == NULL) {
        return RAP_ERROR;
    }

    *ppr = pr;

    pr->request = NULL;
    pr->out = NULL;
    pr->next = NULL;

found:

    if (rap_chain_add_copy(r->pool, &pr->out, in) == RAP_OK) {
        return RAP_OK;
    }

    return RAP_ERROR;
}


static rap_int_t
rap_http_postpone_filter_in_memory(rap_http_request_t *r, rap_chain_t *in)
{
    size_t                     len;
    rap_buf_t                 *b;
    rap_connection_t          *c;
    rap_http_core_loc_conf_t  *clcf;

    c = r->connection;

    rap_log_debug0(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http postpone filter in memory");

    if (r->out == NULL) {
        clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

        if (r->headers_out.content_length_n != -1) {
            len = r->headers_out.content_length_n;

            if (len > clcf->subrequest_output_buffer_size) {
                rap_log_error(RAP_LOG_ERR, c->log, 0,
                              "too big subrequest response: %uz", len);
                return RAP_ERROR;
            }

        } else {
            len = clcf->subrequest_output_buffer_size;
        }

        b = rap_create_temp_buf(r->pool, len);
        if (b == NULL) {
            return RAP_ERROR;
        }

        b->last_buf = 1;

        r->out = rap_alloc_chain_link(r->pool);
        if (r->out == NULL) {
            return RAP_ERROR;
        }

        r->out->buf = b;
        r->out->next = NULL;
    }

    b = r->out->buf;

    for ( /* void */ ; in; in = in->next) {

        if (rap_buf_special(in->buf)) {
            continue;
        }

        len = in->buf->last - in->buf->pos;

        if (len > (size_t) (b->end - b->last)) {
            rap_log_error(RAP_LOG_ERR, c->log, 0,
                          "too big subrequest response");
            return RAP_ERROR;
        }

        rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                       "http postpone filter in memory %uz bytes", len);

        b->last = rap_cpymem(b->last, in->buf->pos, len);
        in->buf->pos = in->buf->last;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_postpone_filter_init(rap_conf_t *cf)
{
    rap_http_next_body_filter = rap_http_top_body_filter;
    rap_http_top_body_filter = rap_http_postpone_filter;

    return RAP_OK;
}
