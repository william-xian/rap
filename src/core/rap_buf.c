
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


rap_buf_t *
rap_create_temp_buf(rap_pool_t *pool, size_t size)
{
    rap_buf_t *b;

    b = rap_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = rap_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by rap_calloc_buf():
     *
     *     b->file_pos = 0;
     *     b->file_last = 0;
     *     b->file = NULL;
     *     b->shadow = NULL;
     *     b->tag = 0;
     *     and flags
     */

    b->pos = b->start;
    b->last = b->start;
    b->end = b->last + size;
    b->temporary = 1;

    return b;
}


rap_chain_t *
rap_alloc_chain_link(rap_pool_t *pool)
{
    rap_chain_t  *cl;

    cl = pool->chain;

    if (cl) {
        pool->chain = cl->next;
        return cl;
    }

    cl = rap_palloc(pool, sizeof(rap_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}


rap_chain_t *
rap_create_chain_of_bufs(rap_pool_t *pool, rap_bufs_t *bufs)
{
    u_char       *p;
    rap_int_t     i;
    rap_buf_t    *b;
    rap_chain_t  *chain, *cl, **ll;

    p = rap_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }

    ll = &chain;

    for (i = 0; i < bufs->num; i++) {

        b = rap_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by rap_calloc_buf():
         *
         *     b->file_pos = 0;
         *     b->file_last = 0;
         *     b->file = NULL;
         *     b->shadow = NULL;
         *     b->tag = 0;
         *     and flags
         *
         */

        b->pos = p;
        b->last = p;
        b->temporary = 1;

        b->start = p;
        p += bufs->size;
        b->end = p;

        cl = rap_alloc_chain_link(pool);
        if (cl == NULL) {
            return NULL;
        }

        cl->buf = b;
        *ll = cl;
        ll = &cl->next;
    }

    *ll = NULL;

    return chain;
}


rap_int_t
rap_chain_add_copy(rap_pool_t *pool, rap_chain_t **chain, rap_chain_t *in)
{
    rap_chain_t  *cl, **ll;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        cl = rap_alloc_chain_link(pool);
        if (cl == NULL) {
            *ll = NULL;
            return RAP_ERROR;
        }

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return RAP_OK;
}


rap_chain_t *
rap_chain_get_free_buf(rap_pool_t *p, rap_chain_t **free)
{
    rap_chain_t  *cl;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }

    cl = rap_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = rap_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}


void
rap_chain_update_chains(rap_pool_t *p, rap_chain_t **free, rap_chain_t **busy,
    rap_chain_t **out, rap_buf_tag_t tag)
{
    rap_chain_t  *cl;

    if (*out) {
        if (*busy == NULL) {
            *busy = *out;

        } else {
            for (cl = *busy; cl->next; cl = cl->next) { /* void */ }

            cl->next = *out;
        }

        *out = NULL;
    }

    while (*busy) {
        cl = *busy;

        if (rap_buf_size(cl->buf) != 0) {
            break;
        }

        if (cl->buf->tag != tag) {
            *busy = cl->next;
            rap_free_chain(p, cl);
            continue;
        }

        cl->buf->pos = cl->buf->start;
        cl->buf->last = cl->buf->start;

        *busy = cl->next;
        cl->next = *free;
        *free = cl;
    }
}


off_t
rap_chain_coalesce_file(rap_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    rap_fd_t      fd;
    rap_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
        size = cl->buf->file_last - cl->buf->file_pos;

        if (size > limit - total) {
            size = limit - total;

            aligned = (cl->buf->file_pos + size + rap_pagesize - 1)
                       & ~((off_t) rap_pagesize - 1);

            if (aligned <= cl->buf->file_last) {
                size = aligned - cl->buf->file_pos;
            }

            total += size;
            break;
        }

        total += size;
        fprev = cl->buf->file_pos + size;
        cl = cl->next;

    } while (cl
             && cl->buf->in_file
             && total < limit
             && fd == cl->buf->file->fd
             && fprev == cl->buf->file_pos);

    *in = cl;

    return total;
}


rap_chain_t *
rap_chain_update_sent(rap_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {

        if (rap_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }

        size = rap_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;

            if (rap_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }

            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

        if (rap_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
