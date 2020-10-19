
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


static rap_inline void *rap_palloc_small(rap_pool_t *pool, size_t size,
    rap_uint_t align);
static void *rap_palloc_block(rap_pool_t *pool, size_t size);
static void *rap_palloc_large(rap_pool_t *pool, size_t size);


rap_pool_t *
rap_create_pool(size_t size, rap_log_t *log)
{
    rap_pool_t  *p;

    p = rap_memalign(RAP_POOL_ALIGNMENT, size, log);
    if (p == NULL) {
        return NULL;
    }

    p->d.last = (u_char *) p + sizeof(rap_pool_t);
    p->d.end = (u_char *) p + size;
    p->d.next = NULL;
    p->d.failed = 0;

    size = size - sizeof(rap_pool_t);
    p->max = (size < RAP_MAX_ALLOC_FROM_POOL) ? size : RAP_MAX_ALLOC_FROM_POOL;

    p->current = p;
    p->chain = NULL;
    p->large = NULL;
    p->cleanup = NULL;
    p->log = log;

    return p;
}


void
rap_destroy_pool(rap_pool_t *pool)
{
    rap_pool_t          *p, *n;
    rap_pool_large_t    *l;
    rap_pool_cleanup_t  *c;

    for (c = pool->cleanup; c; c = c->next) {
        if (c->handler) {
            rap_log_debug1(RAP_LOG_DEBUG_ALLOC, pool->log, 0,
                           "run cleanup: %p", c);
            c->handler(c->data);
        }
    }

#if (RAP_DEBUG)

    /*
     * we could allocate the pool->log from this pool
     * so we cannot use this log while free()ing the pool
     */

    for (l = pool->large; l; l = l->next) {
        rap_log_debug1(RAP_LOG_DEBUG_ALLOC, pool->log, 0, "free: %p", l->alloc);
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        rap_log_debug2(RAP_LOG_DEBUG_ALLOC, pool->log, 0,
                       "free: %p, unused: %uz", p, p->d.end - p->d.last);

        if (n == NULL) {
            break;
        }
    }

#endif

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            rap_free(l->alloc);
        }
    }

    for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
        rap_free(p);

        if (n == NULL) {
            break;
        }
    }
}


void
rap_reset_pool(rap_pool_t *pool)
{
    rap_pool_t        *p;
    rap_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (l->alloc) {
            rap_free(l->alloc);
        }
    }

    for (p = pool; p; p = p->d.next) {
        p->d.last = (u_char *) p + sizeof(rap_pool_t);
        p->d.failed = 0;
    }

    pool->current = pool;
    pool->chain = NULL;
    pool->large = NULL;
}


void *
rap_palloc(rap_pool_t *pool, size_t size)
{
#if !(RAP_DEBUG_PALLOC)
    if (size <= pool->max) {
        return rap_palloc_small(pool, size, 1);
    }
#endif

    return rap_palloc_large(pool, size);
}


void *
rap_pnalloc(rap_pool_t *pool, size_t size)
{
#if !(RAP_DEBUG_PALLOC)
    if (size <= pool->max) {
        return rap_palloc_small(pool, size, 0);
    }
#endif

    return rap_palloc_large(pool, size);
}


static rap_inline void *
rap_palloc_small(rap_pool_t *pool, size_t size, rap_uint_t align)
{
    u_char      *m;
    rap_pool_t  *p;

    p = pool->current;

    do {
        m = p->d.last;

        if (align) {
            m = rap_align_ptr(m, RAP_ALIGNMENT);
        }

        if ((size_t) (p->d.end - m) >= size) {
            p->d.last = m + size;

            return m;
        }

        p = p->d.next;

    } while (p);

    return rap_palloc_block(pool, size);
}


static void *
rap_palloc_block(rap_pool_t *pool, size_t size)
{
    u_char      *m;
    size_t       psize;
    rap_pool_t  *p, *new;

    psize = (size_t) (pool->d.end - (u_char *) pool);

    m = rap_memalign(RAP_POOL_ALIGNMENT, psize, pool->log);
    if (m == NULL) {
        return NULL;
    }

    new = (rap_pool_t *) m;

    new->d.end = m + psize;
    new->d.next = NULL;
    new->d.failed = 0;

    m += sizeof(rap_pool_data_t);
    m = rap_align_ptr(m, RAP_ALIGNMENT);
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
rap_palloc_large(rap_pool_t *pool, size_t size)
{
    void              *p;
    rap_uint_t         n;
    rap_pool_large_t  *large;

    p = rap_alloc(size, pool->log);
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

    large = rap_palloc_small(pool, sizeof(rap_pool_large_t), 1);
    if (large == NULL) {
        rap_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


void *
rap_pmemalign(rap_pool_t *pool, size_t size, size_t alignment)
{
    void              *p;
    rap_pool_large_t  *large;

    p = rap_memalign(alignment, size, pool->log);
    if (p == NULL) {
        return NULL;
    }

    large = rap_palloc_small(pool, sizeof(rap_pool_large_t), 1);
    if (large == NULL) {
        rap_free(p);
        return NULL;
    }

    large->alloc = p;
    large->next = pool->large;
    pool->large = large;

    return p;
}


rap_int_t
rap_pfree(rap_pool_t *pool, void *p)
{
    rap_pool_large_t  *l;

    for (l = pool->large; l; l = l->next) {
        if (p == l->alloc) {
            rap_log_debug1(RAP_LOG_DEBUG_ALLOC, pool->log, 0,
                           "free: %p", l->alloc);
            rap_free(l->alloc);
            l->alloc = NULL;

            return RAP_OK;
        }
    }

    return RAP_DECLINED;
}


void *
rap_pcalloc(rap_pool_t *pool, size_t size)
{
    void *p;

    p = rap_palloc(pool, size);
    if (p) {
        rap_memzero(p, size);
    }

    return p;
}


rap_pool_cleanup_t *
rap_pool_cleanup_add(rap_pool_t *p, size_t size)
{
    rap_pool_cleanup_t  *c;

    c = rap_palloc(p, sizeof(rap_pool_cleanup_t));
    if (c == NULL) {
        return NULL;
    }

    if (size) {
        c->data = rap_palloc(p, size);
        if (c->data == NULL) {
            return NULL;
        }

    } else {
        c->data = NULL;
    }

    c->handler = NULL;
    c->next = p->cleanup;

    p->cleanup = c;

    rap_log_debug1(RAP_LOG_DEBUG_ALLOC, p->log, 0, "add cleanup: %p", c);

    return c;
}


void
rap_pool_run_cleanup_file(rap_pool_t *p, rap_fd_t fd)
{
    rap_pool_cleanup_t       *c;
    rap_pool_cleanup_file_t  *cf;

    for (c = p->cleanup; c; c = c->next) {
        if (c->handler == rap_pool_cleanup_file) {

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
rap_pool_cleanup_file(void *data)
{
    rap_pool_cleanup_file_t  *c = data;

    rap_log_debug1(RAP_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d",
                   c->fd);

    if (rap_close_file(c->fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, c->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", c->name);
    }
}


void
rap_pool_delete_file(void *data)
{
    rap_pool_cleanup_file_t  *c = data;

    rap_err_t  err;

    rap_log_debug2(RAP_LOG_DEBUG_ALLOC, c->log, 0, "file cleanup: fd:%d %s",
                   c->fd, c->name);

    if (rap_delete_file(c->name) == RAP_FILE_ERROR) {
        err = rap_errno;

        if (err != RAP_ENOENT) {
            rap_log_error(RAP_LOG_CRIT, c->log, err,
                          rap_delete_file_n " \"%s\" failed", c->name);
        }
    }

    if (rap_close_file(c->fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, c->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", c->name);
    }
}


#if 0

static void *
rap_get_cached_block(size_t size)
{
    void                     *p;
    rap_cached_block_slot_t  *slot;

    if (rap_cycle->cache == NULL) {
        return NULL;
    }

    slot = &rap_cycle->cache[(size + rap_pagesize - 1) / rap_pagesize];

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
