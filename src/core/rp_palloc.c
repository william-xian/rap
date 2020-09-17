
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


static rp_inline void *rp_palloc_small(rp_pool_t *pool, size_t size,
    rp_uint_t align);
static void *rp_palloc_block(rp_pool_t *pool, size_t size);
static void *rp_palloc_large(rp_pool_t *pool, size_t size);


rp_pool_t *
rp_create_pool(size_t size, rp_log_t *log)
{
    rp_pool_t  *p;

    p = rp_memalign(RP_POOL_ALIGNMENT, size, log);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char *) p + sizeof(rp_pool_t);
    p->d.end = (u_char *) p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    size = size - sizeof(rp_pool_t);
    p->max = (size < RP_MAX_ALLOC_FROM_POOL) ? size : RP_MAX_ALLOC_FROM_POOL;

    p->current = p;
    p->chain = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;

    return p;
}


void
rp_destroy_pool(rp_pool_t *pool)
{
    rp_pool_t          *p, *n;
    rp_pool_large_t    *l;
    rp_pool_cleanup_t  *c;

    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            rp_log_debug1(RP_LOG_DEBUG_ALLOC, pool->log, 0,
                           "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

#if (RP_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we cannot use this log while free()ing the pool
     */

    for (l = pool->large; l; l = l->next) {
        rp_log_debug1(RP_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        rp_log_debug2(RP_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->d.end - p->d.last);

        if (n == NULL) {
            break;
        }
    }

#endif

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            rp_free(l->alloc);
        }
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        rp_free(p);

        if (n == NULL) {
            break;
        }
    }
}


void
rp_reset_pool(rp_pool_t *pool)
{
    rp_pool_t        *p;
    rp_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            rp_free(l->alloc);
        }
    }

    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *) p + sizeof(rp_pool_t);
        p->d.failed = 0;
    }

    pool->current = pool;
    pool->chain = NULL;
    pool->large = NULL;
}


void *
rp_palloc(rp_pool_t *pool, size_t size)
{
#if !(RP_DEBUG_PALLOC)
    if (size <= pool->max) {
        return rp_palloc_small(pool, size, 1);
    }
#endif

    return rp_palloc_large(pool, size);
}


void *
rp_pnalloc(rp_pool_t *pool, size_t size)
{
#if !(RP_DEBUG_PALLOC)
    if (size <= pool->max) {
        return rp_palloc_small(pool, size, 0);
    }
#endif

    return rp_palloc_large(pool, size);
}


static rp_inline void *
rp_palloc_small(rp_pool_t *pool, size_t size, rp_uint_t align)
{
    u_char      *m;
    rp_pool_t  *p;

    p = pool->current;

    do {
        m = p->d.last;

        if (align) {
            m = rp_align_ptr(m, RP_ALIGNMENT);
        }

        if ((size_t) (p->d.end - m) >= size) {
            p->d.last = m + size;

            return m;
        }

        p = p->d.next;

    } while (p);

    return rp_palloc_block(pool, size);
}


static void *
rp_palloc_block(rp_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    rp_pool_t  *p, *new;

    psize = (size_t) (pool->d.end - (u_char *) pool);

    m = rp_memalign(RP_POOL_ALIGNMENT, psize, pool->log);
    if (m == NULL) {
        return NULL;
    }

    new = (rp_pool_t *) m;

    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    m += sizeof(rp_pool_data_t);
    m = rp_align_ptr(m, RP_ALIGNMENT);
    new->d.last = m + size;

    for (p = pool->current; p->d.next; p = p->d.next) {
        if (p->d.failed++ > 4) {
            pool->current = p->d.next;
        }
    }

    p->d.next = new;

    return m;
}


static void *
rp_palloc_large(rp_pool_t *pool, size_t size)
{
    void              *p;
    rp_uint_t         n;
    rp_pool_large_t  *large;

    p = rp_alloc(size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    n = 0;

    for (large = pool->large; large; large = large->next) {
        if (large->alloc == NULL) {
            large->alloc = p;
            return p;
        }

        if (n++ > 3) {
            break;
        }
    }

    large = rp_palloc_small(pool, sizeof(rp_pool_large_t), 1);
    if (large == NULL) {
        rp_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


void *
rp_pmemalign(rp_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    rp_pool_large_t  *large;

    p = rp_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    large = rp_palloc_small(pool, sizeof(rp_pool_large_t), 1);
    if (large == NULL) {
        rp_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


rp_int_t
rp_pfree(rp_pool_t *pool, void *p)
{
    rp_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            rp_log_debug1(RP_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            rp_free(l->alloc);
            l->alloc = NULL;

            return RP_OK;
        }
    }

    return RP_DECLINED;
}


void *
rp_pcalloc(rp_pool_t *pool, size_t size)
{
    void *p;

    p = rp_palloc(pool, size);
    if (p) {
        rp_memzero(p, size);
    }

    return p;
}


rp_pool_cleanup_t *
rp_pool_cleanup_add(rp_pool_t *p, size_t size)
{
    rp_pool_cleanup_t  *c;

    c = rp_palloc(p, sizeof(rp_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = rp_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    rp_log_debug1(RP_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}


void
rp_pool_run_cleanup_file(rp_pool_t *p, rp_fd_t fd)
{
    rp_pool_cleanup_t       *c;
    rp_pool_cleanup_file_t  *cf;

    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == rp_pool_cleanup_file) {

            cf = c->data;

            if (cf->fd == fd) {
                c->handler(cf);
                c->handler = NULL;
                return;
            }
        }
    }
}


void
rp_pool_cleanup_file(void *data)
{
    rp_pool_cleanup_file_t  *c = data;

    rp_log_debug1(RP_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
                   c->fd);

    if (rp_close_file(c->fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, c->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", c->name);
    }
}


void
rp_pool_delete_file(void *data)
{
    rp_pool_cleanup_file_t  *c = data;

    rp_err_t  err;

    rp_log_debug2(RP_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
                   c->fd, c->name);

    if (rp_delete_file(c->name) == RP_FILE_ERROR) {
        err = rp_errno;

        if (err != RP_ENOENT) {
            rp_log_error(RP_LOG_CRIT, c->log, err,
                          rp_delete_file_n " \"%s\" failed", c->name);
        }
    }

    if (rp_close_file(c->fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, c->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
rp_get_cached_block(size_t size)
{
    void                     *p;
    rp_cached_block_slot_t  *slot;

    if (rp_cycle->cache == NULL) {
        return NULL;
    }

    slot = &rp_cycle->cache[(size + rp_pagesize - 1) / rp_pagesize];

    slot->tries++;

    if (slot->number) {
        p = slot->block;
        slot->block = slot->block->next;
        slot->number--;
        return p;
    }

    return NULL;
}

#endif
