
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


rp_buf_t *
rp_create_temp_buf(rp_pool_t *pool, size_t size)
{
    rp_buf_t *b;

    b = rp_calloc_buf(pool);
    if (b == NULL) {
        return NULL;
    }

    b->start = rp_palloc(pool, size);
    if (b->start == NULL) {
        return NULL;
    }

    /*
     * set by rp_calloc_buf():
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


rp_chain_t *
rp_alloc_chain_link(rp_pool_t *pool)
{
    rp_chain_t  *cl;

    cl = pool->chain;

    if (cl) {
        pool->chain = cl->next;
        return cl;
    }

    cl = rp_palloc(pool, sizeof(rp_chain_t));
    if (cl == NULL) {
        return NULL;
    }

    return cl;
}


rp_chain_t *
rp_create_chain_of_bufs(rp_pool_t *pool, rp_bufs_t *bufs)
{
    u_char       *p;
    rp_int_t     i;
    rp_buf_t    *b;
    rp_chain_t  *chain, *cl, **ll;

    p = rp_palloc(pool, bufs->num * bufs->size);
    if (p == NULL) {
        return NULL;
    }

    ll = &chain;

    for (i = 0; i < bufs->num; i++) {

        b = rp_calloc_buf(pool);
        if (b == NULL) {
            return NULL;
        }

        /*
         * set by rp_calloc_buf():
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

        cl = rp_alloc_chain_link(pool);
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


rp_int_t
rp_chain_add_copy(rp_pool_t *pool, rp_chain_t **chain, rp_chain_t *in)
{
    rp_chain_t  *cl, **ll;

    ll = chain;

    for (cl = *chain; cl; cl = cl->next) {
        ll = &cl->next;
    }

    while (in) {
        cl = rp_alloc_chain_link(pool);
        if (cl == NULL) {
            *ll = NULL;
            return RP_ERROR;
        }

        cl->buf = in->buf;
        *ll = cl;
        ll = &cl->next;
        in = in->next;
    }

    *ll = NULL;

    return RP_OK;
}


rp_chain_t *
rp_chain_get_free_buf(rp_pool_t *p, rp_chain_t **free)
{
    rp_chain_t  *cl;

    if (*free) {
        cl = *free;
        *free = cl->next;
        cl->next = NULL;
        return cl;
    }

    cl = rp_alloc_chain_link(p);
    if (cl == NULL) {
        return NULL;
    }

    cl->buf = rp_calloc_buf(p);
    if (cl->buf == NULL) {
        return NULL;
    }

    cl->next = NULL;

    return cl;
}


void
rp_chain_update_chains(rp_pool_t *p, rp_chain_t **free, rp_chain_t **busy,
    rp_chain_t **out, rp_buf_tag_t tag)
{
    rp_chain_t  *cl;

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

        if (rp_buf_size(cl->buf) != 0) {
            break;
        }

        if (cl->buf->tag != tag) {
            *busy = cl->next;
            rp_free_chain(p, cl);
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
rp_chain_coalesce_file(rp_chain_t **in, off_t limit)
{
    off_t         total, size, aligned, fprev;
    rp_fd_t      fd;
    rp_chain_t  *cl;

    total = 0;

    cl = *in;
    fd = cl->buf->file->fd;

    do {
        size = cl->buf->file_last - cl->buf->file_pos;

        if (size > limit - total) {
            size = limit - total;

            aligned = (cl->buf->file_pos + size + rp_pagesize - 1)
                       & ~((off_t) rp_pagesize - 1);

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


rp_chain_t *
rp_chain_update_sent(rp_chain_t *in, off_t sent)
{
    off_t  size;

    for ( /* void */ ; in; in = in->next) {

        if (rp_buf_special(in->buf)) {
            continue;
        }

        if (sent == 0) {
            break;
        }

        size = rp_buf_size(in->buf);

        if (sent >= size) {
            sent -= size;

            if (rp_buf_in_memory(in->buf)) {
                in->buf->pos = in->buf->last;
            }

            if (in->buf->in_file) {
                in->buf->file_pos = in->buf->file_last;
            }

            continue;
        }

        if (rp_buf_in_memory(in->buf)) {
            in->buf->pos += (size_t) sent;
        }

        if (in->buf->in_file) {
            in->buf->file_pos += sent;
        }

        break;
    }

    return in;
}
