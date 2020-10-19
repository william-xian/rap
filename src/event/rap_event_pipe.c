
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_event.h>
#include <rap_event_pipe.h>


static rap_int_t rap_event_pipe_read_upstream(rap_event_pipe_t *p);
static rap_int_t rap_event_pipe_write_to_downstream(rap_event_pipe_t *p);

static rap_int_t rap_event_pipe_write_chain_to_temp_file(rap_event_pipe_t *p);
static rap_inline void rap_event_pipe_remove_shadow_links(rap_buf_t *buf);
static rap_int_t rap_event_pipe_drain_chains(rap_event_pipe_t *p);


rap_int_t
rap_event_pipe(rap_event_pipe_t *p, rap_int_t do_write)
{
    rap_int_t     rc;
    rap_uint_t    flags;
    rap_event_t  *rev, *wev;

    for ( ;; ) {
        if (do_write) {
            p->log->action = "sending to client";

            rc = rap_event_pipe_write_to_downstream(p);

            if (rc == RAP_ABORT) {
                return RAP_ABORT;
            }

            if (rc == RAP_BUSY) {
                return RAP_OK;
            }
        }

        p->read = 0;
        p->upstream_blocked = 0;

        p->log->action = "reading upstream";

        if (rap_event_pipe_read_upstream(p) == RAP_ABORT) {
            return RAP_ABORT;
        }

        if (!p->read && !p->upstream_blocked) {
            break;
        }

        do_write = 1;
    }

    if (p->upstream->fd != (rap_socket_t) -1) {
        rev = p->upstream->read;

        flags = (rev->eof || rev->error) ? RAP_CLOSE_EVENT : 0;

        if (rap_handle_read_event(rev, flags) != RAP_OK) {
            return RAP_ABORT;
        }

        if (!rev->delayed) {
            if (rev->active && !rev->ready) {
                rap_add_timer(rev, p->read_timeout);

            } else if (rev->timer_set) {
                rap_del_timer(rev);
            }
        }
    }

    if (p->downstream->fd != (rap_socket_t) -1
        && p->downstream->data == p->output_ctx)
    {
        wev = p->downstream->write;
        if (rap_handle_write_event(wev, p->send_lowat) != RAP_OK) {
            return RAP_ABORT;
        }

        if (!wev->delayed) {
            if (wev->active && !wev->ready) {
                rap_add_timer(wev, p->send_timeout);

            } else if (wev->timer_set) {
                rap_del_timer(wev);
            }
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_event_pipe_read_upstream(rap_event_pipe_t *p)
{
    off_t         limit;
    ssize_t       n, size;
    rap_int_t     rc;
    rap_buf_t    *b;
    rap_msec_t    delay;
    rap_chain_t  *chain, *cl, *ln;

    if (p->upstream_eof || p->upstream_error || p->upstream_done) {
        return RAP_OK;
    }

#if (RAP_THREADS)

    if (p->aio) {
        rap_log_debug0(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe read upstream: aio");
        return RAP_AGAIN;
    }

    if (p->writing) {
        rap_log_debug0(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe read upstream: writing");

        rc = rap_event_pipe_write_chain_to_temp_file(p);

        if (rc != RAP_OK) {
            return rc;
        }
    }

#endif

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe read upstream: %d", p->upstream->read->ready);

    for ( ;; ) {

        if (p->upstream_eof || p->upstream_error || p->upstream_done) {
            break;
        }

        if (p->preread_bufs == NULL && !p->upstream->read->ready) {
            break;
        }

        if (p->preread_bufs) {

            /* use the pre-read bufs if they exist */

            chain = p->preread_bufs;
            p->preread_bufs = NULL;
            n = p->preread_size;

            rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe preread: %z", n);

            if (n) {
                p->read = 1;
            }

        } else {

#if (RAP_HAVE_KQUEUE)

            /*
             * kqueue notifies about the end of file or a pending error.
             * This test allows not to allocate a buf on these conditions
             * and not to call c->recv_chain().
             */

            if (p->upstream->read->available == 0
                && p->upstream->read->pending_eof
#if (RAP_SSL)
                && !p->upstream->ssl
#endif
                )
            {
                p->upstream->read->ready = 0;
                p->upstream->read->eof = 1;
                p->upstream_eof = 1;
                p->read = 1;

                if (p->upstream->read->kq_errno) {
                    p->upstream->read->error = 1;
                    p->upstream_error = 1;
                    p->upstream_eof = 0;

                    rap_log_error(RAP_LOG_ERR, p->log,
                                  p->upstream->read->kq_errno,
                                  "kevent() reported that upstream "
                                  "closed connection");
                }

                break;
            }
#endif

            if (p->limit_rate) {
                if (p->upstream->read->delayed) {
                    break;
                }

                limit = (off_t) p->limit_rate * (rap_time() - p->start_sec + 1)
                        - p->read_length;

                if (limit <= 0) {
                    p->upstream->read->delayed = 1;
                    delay = (rap_msec_t) (- limit * 1000 / p->limit_rate + 1);
                    rap_add_timer(p->upstream->read, delay);
                    break;
                }

            } else {
                limit = 0;
            }

            if (p->free_raw_bufs) {

                /* use the free bufs if they exist */

                chain = p->free_raw_bufs;
                if (p->single_buf) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;
                }

            } else if (p->allocated < p->bufs.num) {

                /* allocate a new buf if it's still allowed */

                b = rap_create_temp_buf(p->pool, p->bufs.size);
                if (b == NULL) {
                    return RAP_ABORT;
                }

                p->allocated++;

                chain = rap_alloc_chain_link(p->pool);
                if (chain == NULL) {
                    return RAP_ABORT;
                }

                chain->buf = b;
                chain->next = NULL;

            } else if (!p->cacheable
                       && p->downstream->data == p->output_ctx
                       && p->downstream->write->ready
                       && !p->downstream->write->delayed)
            {
                /*
                 * if the bufs are not needed to be saved in a cache and
                 * a downstream is ready then write the bufs to a downstream
                 */

                p->upstream_blocked = 1;

                rap_log_debug0(RAP_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe downstream ready");

                break;

            } else if (p->cacheable
                       || p->temp_file->offset < p->max_temp_file_size)
            {

                /*
                 * if it is allowed, then save some bufs from p->in
                 * to a temporary file, and add them to a p->out chain
                 */

                rc = rap_event_pipe_write_chain_to_temp_file(p);

                rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe temp offset: %O", p->temp_file->offset);

                if (rc == RAP_BUSY) {
                    break;
                }

                if (rc != RAP_OK) {
                    return rc;
                }

                chain = p->free_raw_bufs;
                if (p->single_buf) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;
                }

            } else {

                /* there are no bufs to read in */

                rap_log_debug0(RAP_LOG_DEBUG_EVENT, p->log, 0,
                               "no pipe bufs to read in");

                break;
            }

            n = p->upstream->recv_chain(p->upstream, chain, limit);

            rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe recv chain: %z", n);

            if (p->free_raw_bufs) {
                chain->next = p->free_raw_bufs;
            }
            p->free_raw_bufs = chain;

            if (n == RAP_ERROR) {
                p->upstream_error = 1;
                break;
            }

            if (n == RAP_AGAIN) {
                if (p->single_buf) {
                    rap_event_pipe_remove_shadow_links(chain->buf);
                }

                break;
            }

            p->read = 1;

            if (n == 0) {
                p->upstream_eof = 1;
                break;
            }
        }

        delay = p->limit_rate ? (rap_msec_t) n * 1000 / p->limit_rate : 0;

        p->read_length += n;
        cl = chain;
        p->free_raw_bufs = NULL;

        while (cl && n > 0) {

            rap_event_pipe_remove_shadow_links(cl->buf);

            size = cl->buf->end - cl->buf->last;

            if (n >= size) {
                cl->buf->last = cl->buf->end;

                /* STUB */ cl->buf->num = p->num++;

                if (p->input_filter(p, cl->buf) == RAP_ERROR) {
                    return RAP_ABORT;
                }

                n -= size;
                ln = cl;
                cl = cl->next;
                rap_free_chain(p->pool, ln);

            } else {
                cl->buf->last += n;
                n = 0;
            }
        }

        if (cl) {
            for (ln = cl; ln->next; ln = ln->next) { /* void */ }

            ln->next = p->free_raw_bufs;
            p->free_raw_bufs = cl;
        }

        if (delay > 0) {
            p->upstream->read->delayed = 1;
            rap_add_timer(p->upstream->read, delay);
            break;
        }
    }

#if (RAP_DEBUG)

    for (cl = p->busy; cl; cl = cl->next) {
        rap_log_debug8(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf busy s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->out; cl; cl = cl->next) {
        rap_log_debug8(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf out  s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->in; cl; cl = cl->next) {
        rap_log_debug8(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf in   s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->free_raw_bufs; cl; cl = cl->next) {
        rap_log_debug8(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf free s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %O",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe length: %O", p->length);

#endif

    if (p->free_raw_bufs && p->length != -1) {
        cl = p->free_raw_bufs;

        if (cl->buf->last - cl->buf->pos >= p->length) {

            p->free_raw_bufs = cl->next;

            /* STUB */ cl->buf->num = p->num++;

            if (p->input_filter(p, cl->buf) == RAP_ERROR) {
                return RAP_ABORT;
            }

            rap_free_chain(p->pool, cl);
        }
    }

    if (p->length == 0) {
        p->upstream_done = 1;
        p->read = 1;
    }

    if ((p->upstream_eof || p->upstream_error) && p->free_raw_bufs) {

        /* STUB */ p->free_raw_bufs->buf->num = p->num++;

        if (p->input_filter(p, p->free_raw_bufs->buf) == RAP_ERROR) {
            return RAP_ABORT;
        }

        p->free_raw_bufs = p->free_raw_bufs->next;

        if (p->free_bufs && p->buf_to_file == NULL) {
            for (cl = p->free_raw_bufs; cl; cl = cl->next) {
                if (cl->buf->shadow == NULL) {
                    rap_pfree(p->pool, cl->buf->start);
                }
            }
        }
    }

    if (p->cacheable && (p->in || p->buf_to_file)) {

        rap_log_debug0(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write chain");

        rc = rap_event_pipe_write_chain_to_temp_file(p);

        if (rc != RAP_OK) {
            return rc;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_event_pipe_write_to_downstream(rap_event_pipe_t *p)
{
    u_char            *prev;
    size_t             bsize;
    rap_int_t          rc;
    rap_uint_t         flush, flushed, prev_last_shadow;
    rap_chain_t       *out, **ll, *cl;
    rap_connection_t  *downstream;

    downstream = p->downstream;

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe write downstream: %d", downstream->write->ready);

#if (RAP_THREADS)

    if (p->writing) {
        rc = rap_event_pipe_write_chain_to_temp_file(p);

        if (rc == RAP_ABORT) {
            return RAP_ABORT;
        }
    }

#endif

    flushed = 0;

    for ( ;; ) {
        if (p->downstream_error) {
            return rap_event_pipe_drain_chains(p);
        }

        if (p->upstream_eof || p->upstream_error || p->upstream_done) {

            /* pass the p->out and p->in chains to the output filter */

            for (cl = p->busy; cl; cl = cl->next) {
                cl->buf->recycled = 0;
            }

            if (p->out) {
                rap_log_debug0(RAP_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush out");

                for (cl = p->out; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                rc = p->output_filter(p->output_ctx, p->out);

                if (rc == RAP_ERROR) {
                    p->downstream_error = 1;
                    return rap_event_pipe_drain_chains(p);
                }

                p->out = NULL;
            }

            if (p->writing) {
                break;
            }

            if (p->in) {
                rap_log_debug0(RAP_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush in");

                for (cl = p->in; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                rc = p->output_filter(p->output_ctx, p->in);

                if (rc == RAP_ERROR) {
                    p->downstream_error = 1;
                    return rap_event_pipe_drain_chains(p);
                }

                p->in = NULL;
            }

            rap_log_debug0(RAP_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe write downstream done");

            /* TODO: free unused bufs */

            p->downstream_done = 1;
            break;
        }

        if (downstream->data != p->output_ctx
            || !downstream->write->ready
            || downstream->write->delayed)
        {
            break;
        }

        /* bsize is the size of the busy recycled bufs */

        prev = NULL;
        bsize = 0;

        for (cl = p->busy; cl; cl = cl->next) {

            if (cl->buf->recycled) {
                if (prev == cl->buf->start) {
                    continue;
                }

                bsize += cl->buf->end - cl->buf->start;
                prev = cl->buf->start;
            }
        }

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write busy: %uz", bsize);

        out = NULL;

        if (bsize >= (size_t) p->busy_size) {
            flush = 1;
            goto flush;
        }

        flush = 0;
        ll = NULL;
        prev_last_shadow = 1;

        for ( ;; ) {
            if (p->out) {
                cl = p->out;

                if (cl->buf->recycled) {
                    rap_log_error(RAP_LOG_ALERT, p->log, 0,
                                  "recycled buffer in pipe out chain");
                }

                p->out = p->out->next;

            } else if (!p->cacheable && !p->writing && p->in) {
                cl = p->in;

                rap_log_debug3(RAP_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write buf ls:%d %p %z",
                               cl->buf->last_shadow,
                               cl->buf->pos,
                               cl->buf->last - cl->buf->pos);

                if (cl->buf->recycled && prev_last_shadow) {
                    if (bsize + cl->buf->end - cl->buf->start > p->busy_size) {
                        flush = 1;
                        break;
                    }

                    bsize += cl->buf->end - cl->buf->start;
                }

                prev_last_shadow = cl->buf->last_shadow;

                p->in = p->in->next;

            } else {
                break;
            }

            cl->next = NULL;

            if (out) {
                *ll = cl;
            } else {
                out = cl;
            }
            ll = &cl->next;
        }

    flush:

        rap_log_debug2(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write: out:%p, f:%ui", out, flush);

        if (out == NULL) {

            if (!flush) {
                break;
            }

            /* a workaround for AIO */
            if (flushed++ > 10) {
                return RAP_BUSY;
            }
        }

        rc = p->output_filter(p->output_ctx, out);

        rap_chain_update_chains(p->pool, &p->free, &p->busy, &out, p->tag);

        if (rc == RAP_ERROR) {
            p->downstream_error = 1;
            return rap_event_pipe_drain_chains(p);
        }

        for (cl = p->free; cl; cl = cl->next) {

            if (cl->buf->temp_file) {
                if (p->cacheable || !p->cyclic_temp_file) {
                    continue;
                }

                /* reset p->temp_offset if all bufs had been sent */

                if (cl->buf->file_last == p->temp_file->offset) {
                    p->temp_file->offset = 0;
                }
            }

            /* TODO: free buf if p->free_bufs && upstream done */

            /* add the free shadow raw buf to p->free_raw_bufs */

            if (cl->buf->last_shadow) {
                if (rap_event_pipe_add_free_buf(p, cl->buf->shadow) != RAP_OK) {
                    return RAP_ABORT;
                }

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
        }
    }

    return RAP_OK;
}


static rap_int_t
rap_event_pipe_write_chain_to_temp_file(rap_event_pipe_t *p)
{
    ssize_t       size, bsize, n;
    rap_buf_t    *b;
    rap_uint_t    prev_last_shadow;
    rap_chain_t  *cl, *tl, *next, *out, **ll, **last_out, **last_free;

#if (RAP_THREADS)

    if (p->writing) {

        if (p->aio) {
            return RAP_AGAIN;
        }

        out = p->writing;
        p->writing = NULL;

        n = rap_write_chain_to_temp_file(p->temp_file, NULL);

        if (n == RAP_ERROR) {
            return RAP_ABORT;
        }

        goto done;
    }

#endif

    if (p->buf_to_file) {
        out = rap_alloc_chain_link(p->pool);
        if (out == NULL) {
            return RAP_ABORT;
        }

        out->buf = p->buf_to_file;
        out->next = p->in;

    } else {
        out = p->in;
    }

    if (!p->cacheable) {

        size = 0;
        cl = out;
        ll = NULL;
        prev_last_shadow = 1;

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe offset: %O", p->temp_file->offset);

        do {
            bsize = cl->buf->last - cl->buf->pos;

            rap_log_debug4(RAP_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe buf ls:%d %p, pos %p, size: %z",
                           cl->buf->last_shadow, cl->buf->start,
                           cl->buf->pos, bsize);

            if (prev_last_shadow
                && ((size + bsize > p->temp_file_write_size)
                    || (p->temp_file->offset + size + bsize
                        > p->max_temp_file_size)))
            {
                break;
            }

            prev_last_shadow = cl->buf->last_shadow;

            size += bsize;
            ll = &cl->next;
            cl = cl->next;

        } while (cl);

        rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0, "size: %z", size);

        if (ll == NULL) {
            return RAP_BUSY;
        }

        if (cl) {
            p->in = cl;
            *ll = NULL;

        } else {
            p->in = NULL;
            p->last_in = &p->in;
        }

    } else {
        p->in = NULL;
        p->last_in = &p->in;
    }

#if (RAP_THREADS)
    if (p->thread_handler) {
        p->temp_file->thread_write = 1;
        p->temp_file->file.thread_task = p->thread_task;
        p->temp_file->file.thread_handler = p->thread_handler;
        p->temp_file->file.thread_ctx = p->thread_ctx;
    }
#endif

    n = rap_write_chain_to_temp_file(p->temp_file, out);

    if (n == RAP_ERROR) {
        return RAP_ABORT;
    }

#if (RAP_THREADS)

    if (n == RAP_AGAIN) {
        p->writing = out;
        p->thread_task = p->temp_file->file.thread_task;
        return RAP_AGAIN;
    }

done:

#endif

    if (p->buf_to_file) {
        p->temp_file->offset = p->buf_to_file->last - p->buf_to_file->pos;
        n -= p->buf_to_file->last - p->buf_to_file->pos;
        p->buf_to_file = NULL;
        out = out->next;
    }

    if (n > 0) {
        /* update previous buffer or add new buffer */

        if (p->out) {
            for (cl = p->out; cl->next; cl = cl->next) { /* void */ }

            b = cl->buf;

            if (b->file_last == p->temp_file->offset) {
                p->temp_file->offset += n;
                b->file_last = p->temp_file->offset;
                goto free;
            }

            last_out = &cl->next;

        } else {
            last_out = &p->out;
        }

        cl = rap_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return RAP_ABORT;
        }

        b = cl->buf;

        rap_memzero(b, sizeof(rap_buf_t));

        b->tag = p->tag;

        b->file = &p->temp_file->file;
        b->file_pos = p->temp_file->offset;
        p->temp_file->offset += n;
        b->file_last = p->temp_file->offset;

        b->in_file = 1;
        b->temp_file = 1;

        *last_out = cl;
    }

free:

    for (last_free = &p->free_raw_bufs;
         *last_free != NULL;
         last_free = &(*last_free)->next)
    {
        /* void */
    }

    for (cl = out; cl; cl = next) {
        next = cl->next;

        cl->next = p->free;
        p->free = cl;

        b = cl->buf;

        if (b->last_shadow) {

            tl = rap_alloc_chain_link(p->pool);
            if (tl == NULL) {
                return RAP_ABORT;
            }

            tl->buf = b->shadow;
            tl->next = NULL;

            *last_free = tl;
            last_free = &tl->next;

            b->shadow->pos = b->shadow->start;
            b->shadow->last = b->shadow->start;

            rap_event_pipe_remove_shadow_links(b->shadow);
        }
    }

    return RAP_OK;
}


/* the copy input filter */

rap_int_t
rap_event_pipe_copy_input_filter(rap_event_pipe_t *p, rap_buf_t *buf)
{
    rap_buf_t    *b;
    rap_chain_t  *cl;

    if (buf->pos == buf->last) {
        return RAP_OK;
    }

    cl = rap_chain_get_free_buf(p->pool, &p->free);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    b = cl->buf;

    rap_memcpy(b, buf, sizeof(rap_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    rap_log_debug1(RAP_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;

    if (p->length == -1) {
        return RAP_OK;
    }

    p->length -= b->last - b->pos;

    return RAP_OK;
}


static rap_inline void
rap_event_pipe_remove_shadow_links(rap_buf_t *buf)
{
    rap_buf_t  *b, *next;

    b = buf->shadow;

    if (b == NULL) {
        return;
    }

    while (!b->last_shadow) {
        next = b->shadow;

        b->temporary = 0;
        b->recycled = 0;

        b->shadow = NULL;
        b = next;
    }

    b->temporary = 0;
    b->recycled = 0;
    b->last_shadow = 0;

    b->shadow = NULL;

    buf->shadow = NULL;
}


rap_int_t
rap_event_pipe_add_free_buf(rap_event_pipe_t *p, rap_buf_t *b)
{
    rap_chain_t  *cl;

    cl = rap_alloc_chain_link(p->pool);
    if (cl == NULL) {
        return RAP_ERROR;
    }

    if (p->buf_to_file && b->start == p->buf_to_file->start) {
        b->pos = p->buf_to_file->last;
        b->last = p->buf_to_file->last;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    b->shadow = NULL;

    cl->buf = b;

    if (p->free_raw_bufs == NULL) {
        p->free_raw_bufs = cl;
        cl->next = NULL;

        return RAP_OK;
    }

    if (p->free_raw_bufs->buf->pos == p->free_raw_bufs->buf->last) {

        /* add the free buf to the list start */

        cl->next = p->free_raw_bufs;
        p->free_raw_bufs = cl;

        return RAP_OK;
    }

    /* the first free buf is partially filled, thus add the free buf after it */

    cl->next = p->free_raw_bufs->next;
    p->free_raw_bufs->next = cl;

    return RAP_OK;
}


static rap_int_t
rap_event_pipe_drain_chains(rap_event_pipe_t *p)
{
    rap_chain_t  *cl, *tl;

    for ( ;; ) {
        if (p->busy) {
            cl = p->busy;
            p->busy = NULL;

        } else if (p->out) {
            cl = p->out;
            p->out = NULL;

        } else if (p->in) {
            cl = p->in;
            p->in = NULL;

        } else {
            return RAP_OK;
        }

        while (cl) {
            if (cl->buf->last_shadow) {
                if (rap_event_pipe_add_free_buf(p, cl->buf->shadow) != RAP_OK) {
                    return RAP_ABORT;
                }

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
            tl = cl->next;
            cl->next = p->free;
            p->free = cl;
            cl = tl;
        }
    }
}
