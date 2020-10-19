
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static rap_int_t rap_http_write_filter_init(rap_conf_t *cf);


static rap_http_module_t  rap_http_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rap_http_write_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


rap_module_t  rap_http_write_filter_module = {
    RAP_MODULE_V1,
    &rap_http_write_filter_module_ctx,     /* module context */
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


rap_int_t
rap_http_write_filter(rap_http_request_t *r, rap_chain_t *in)
{
    off_t                      size, sent, nsent, limit;
    rap_uint_t                 last, flush, sync;
    rap_msec_t                 delay;
    rap_chain_t               *cl, *ln, **ll, *chain;
    rap_connection_t          *c;
    rap_http_core_loc_conf_t  *clcf;

    c = r->connection;

    if (c->error) {
        return RAP_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        rap_log_debug7(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (rap_buf_size(cl->buf) == 0 && !rap_buf_special(cl->buf)) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            rap_debug_point();
            return RAP_ERROR;
        }

        if (rap_buf_size(cl->buf) < 0) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            rap_debug_point();
            return RAP_ERROR;
        }

        size += rap_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    /* add the new chain to the existent one */

    for (ln = in; ln; ln = ln->next) {
        cl = rap_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RAP_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        rap_log_debug7(RAP_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (rap_buf_size(cl->buf) == 0 && !rap_buf_special(cl->buf)) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
                          "zero size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            rap_debug_point();
            return RAP_ERROR;
        }

        if (rap_buf_size(cl->buf) < 0) {
            rap_log_error(RAP_LOG_ALERT, c->log, 0,
                          "negative size buf in writer "
                          "t:%d r:%d f:%d %p %p-%p %p %O-%O",
                          cl->buf->temporary,
                          cl->buf->recycled,
                          cl->buf->in_file,
                          cl->buf->start,
                          cl->buf->pos,
                          cl->buf->last,
                          cl->buf->file,
                          cl->buf->file_pos,
                          cl->buf->file_last);

            rap_debug_point();
            return RAP_ERROR;
        }

        size += rap_buf_size(cl->buf);

        if (cl->buf->flush || cl->buf->recycled) {
            flush = 1;
        }

        if (cl->buf->sync) {
            sync = 1;
        }

        if (cl->buf->last_buf) {
            last = 1;
        }
    }

    *ll = NULL;

    rap_log_debug3(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%ui f:%ui s:%O", last, flush, size);

    clcf = rap_http_get_module_loc_conf(r, rap_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
        return RAP_OK;
    }

    if (c->write->delayed) {
        c->buffered |= RAP_HTTP_WRITE_BUFFERED;
        return RAP_AGAIN;
    }

    if (size == 0
        && !(c->buffered & RAP_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf))
    {
        if (last || flush || sync) {
            for (cl = r->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                rap_free_chain(r->pool, ln);
            }

            r->out = NULL;
            c->buffered &= ~RAP_HTTP_WRITE_BUFFERED;

            return RAP_OK;
        }

        rap_log_error(RAP_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        rap_debug_point();

        return RAP_ERROR;
    }

    if (!r->limit_rate_set) {
        r->limit_rate = rap_http_complex_value_size(r, clcf->limit_rate, 0);
        r->limit_rate_set = 1;
    }

    if (r->limit_rate) {

        if (!r->limit_rate_after_set) {
            r->limit_rate_after = rap_http_complex_value_size(r,
                                                    clcf->limit_rate_after, 0);
            r->limit_rate_after_set = 1;
        }

        limit = (off_t) r->limit_rate * (rap_time() - r->start_sec + 1)
                - (c->sent - r->limit_rate_after);

        if (limit <= 0) {
            c->write->delayed = 1;
            delay = (rap_msec_t) (- limit * 1000 / r->limit_rate + 1);
            rap_add_timer(c->write, delay);

            c->buffered |= RAP_HTTP_WRITE_BUFFERED;

            return RAP_AGAIN;
        }

        if (clcf->sendfile_max_chunk
            && (off_t) clcf->sendfile_max_chunk < limit)
        {
            limit = clcf->sendfile_max_chunk;
        }

    } else {
        limit = clcf->sendfile_max_chunk;
    }

    sent = c->sent;

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter limit %O", limit);

    chain = c->send_chain(c, r->out, limit);

    rap_log_debug1(RAP_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == RAP_CHAIN_ERROR) {
        c->error = 1;
        return RAP_ERROR;
    }

    if (r->limit_rate) {

        nsent = c->sent;

        if (r->limit_rate_after) {

            sent -= r->limit_rate_after;
            if (sent < 0) {
                sent = 0;
            }

            nsent -= r->limit_rate_after;
            if (nsent < 0) {
                nsent = 0;
            }
        }

        delay = (rap_msec_t) ((nsent - sent) * 1000 / r->limit_rate);

        if (delay > 0) {
            limit = 0;
            c->write->delayed = 1;
            rap_add_timer(c->write, delay);
        }
    }

    if (limit
        && c->write->ready
        && c->sent - sent >= limit - (off_t) (2 * rap_pagesize))
    {
        c->write->delayed = 1;
        rap_add_timer(c->write, 1);
    }

    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        rap_free_chain(r->pool, ln);
    }

    r->out = chain;

    if (chain) {
        c->buffered |= RAP_HTTP_WRITE_BUFFERED;
        return RAP_AGAIN;
    }

    c->buffered &= ~RAP_HTTP_WRITE_BUFFERED;

    if ((c->buffered & RAP_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return RAP_AGAIN;
    }

    return RAP_OK;
}


static rap_int_t
rap_http_write_filter_init(rap_conf_t *cf)
{
    rap_http_top_body_filter = rap_http_write_filter;

    return RAP_OK;
}
