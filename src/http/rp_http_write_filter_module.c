
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static rp_int_t rp_http_write_filter_init(rp_conf_t *cf);


static rp_http_module_t  rp_http_write_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    rp_http_write_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL,                                  /* merge location configuration */
};


rp_module_t  rp_http_write_filter_module = {
    RP_MODULE_V1,
    &rp_http_write_filter_module_ctx,     /* module context */
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


rp_int_t
rp_http_write_filter(rp_http_request_t *r, rp_chain_t *in)
{
    off_t                      size, sent, nsent, limit;
    rp_uint_t                 last, flush, sync;
    rp_msec_t                 delay;
    rp_chain_t               *cl, *ln, **ll, *chain;
    rp_connection_t          *c;
    rp_http_core_loc_conf_t  *clcf;

    c = r->connection;

    if (c->error) {
        return RP_ERROR;
    }

    size = 0;
    flush = 0;
    sync = 0;
    last = 0;
    ll = &r->out;

    /* find the size, the flush point and the last link of the saved chain */

    for (cl = r->out; cl; cl = cl->next) {
        ll = &cl->next;

        rp_log_debug7(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "write old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (rp_buf_size(cl->buf) == 0 && !rp_buf_special(cl->buf)) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
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

            rp_debug_point();
            return RP_ERROR;
        }

        if (rp_buf_size(cl->buf) < 0) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
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

            rp_debug_point();
            return RP_ERROR;
        }

        size += rp_buf_size(cl->buf);

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
        cl = rp_alloc_chain_link(r->pool);
        if (cl == NULL) {
            return RP_ERROR;
        }

        cl->buf = ln->buf;
        *ll = cl;
        ll = &cl->next;

        rp_log_debug7(RP_LOG_DEBUG_EVENT, c->log, 0,
                       "write new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %O",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);

        if (rp_buf_size(cl->buf) == 0 && !rp_buf_special(cl->buf)) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
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

            rp_debug_point();
            return RP_ERROR;
        }

        if (rp_buf_size(cl->buf) < 0) {
            rp_log_error(RP_LOG_ALERT, c->log, 0,
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

            rp_debug_point();
            return RP_ERROR;
        }

        size += rp_buf_size(cl->buf);

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

    rp_log_debug3(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter: l:%ui f:%ui s:%O", last, flush, size);

    clcf = rp_http_get_module_loc_conf(r, rp_http_core_module);

    /*
     * avoid the output if there are no last buf, no flush point,
     * there are the incoming bufs and the size of all bufs
     * is smaller than "postpone_output" directive
     */

    if (!last && !flush && in && size < (off_t) clcf->postpone_output) {
        return RP_OK;
    }

    if (c->write->delayed) {
        c->buffered |= RP_HTTP_WRITE_BUFFERED;
        return RP_AGAIN;
    }

    if (size == 0
        && !(c->buffered & RP_LOWLEVEL_BUFFERED)
        && !(last && c->need_last_buf))
    {
        if (last || flush || sync) {
            for (cl = r->out; cl; /* void */) {
                ln = cl;
                cl = cl->next;
                rp_free_chain(r->pool, ln);
            }

            r->out = NULL;
            c->buffered &= ~RP_HTTP_WRITE_BUFFERED;

            return RP_OK;
        }

        rp_log_error(RP_LOG_ALERT, c->log, 0,
                      "the http output chain is empty");

        rp_debug_point();

        return RP_ERROR;
    }

    if (!r->limit_rate_set) {
        r->limit_rate = rp_http_complex_value_size(r, clcf->limit_rate, 0);
        r->limit_rate_set = 1;
    }

    if (r->limit_rate) {

        if (!r->limit_rate_after_set) {
            r->limit_rate_after = rp_http_complex_value_size(r,
                                                    clcf->limit_rate_after, 0);
            r->limit_rate_after_set = 1;
        }

        limit = (off_t) r->limit_rate * (rp_time() - r->start_sec + 1)
                - (c->sent - r->limit_rate_after);

        if (limit <= 0) {
            c->write->delayed = 1;
            delay = (rp_msec_t) (- limit * 1000 / r->limit_rate + 1);
            rp_add_timer(c->write, delay);

            c->buffered |= RP_HTTP_WRITE_BUFFERED;

            return RP_AGAIN;
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

    rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter limit %O", limit);

    chain = c->send_chain(c, r->out, limit);

    rp_log_debug1(RP_LOG_DEBUG_HTTP, c->log, 0,
                   "http write filter %p", chain);

    if (chain == RP_CHAIN_ERROR) {
        c->error = 1;
        return RP_ERROR;
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

        delay = (rp_msec_t) ((nsent - sent) * 1000 / r->limit_rate);

        if (delay > 0) {
            limit = 0;
            c->write->delayed = 1;
            rp_add_timer(c->write, delay);
        }
    }

    if (limit
        && c->write->ready
        && c->sent - sent >= limit - (off_t) (2 * rp_pagesize))
    {
        c->write->delayed = 1;
        rp_add_timer(c->write, 1);
    }

    for (cl = r->out; cl && cl != chain; /* void */) {
        ln = cl;
        cl = cl->next;
        rp_free_chain(r->pool, ln);
    }

    r->out = chain;

    if (chain) {
        c->buffered |= RP_HTTP_WRITE_BUFFERED;
        return RP_AGAIN;
    }

    c->buffered &= ~RP_HTTP_WRITE_BUFFERED;

    if ((c->buffered & RP_LOWLEVEL_BUFFERED) && r->postponed == NULL) {
        return RP_AGAIN;
    }

    return RP_OK;
}


static rp_int_t
rp_http_write_filter_init(rp_conf_t *cf)
{
    rp_http_top_body_filter = rp_http_write_filter;

    return RP_OK;
}
