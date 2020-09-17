
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */

#include <rp_config.h>
#include <rp_core.h>


#define RP_SLAB_PAGE_MASK   3
#define RP_SLAB_PAGE        0
#define RP_SLAB_BIG         1
#define RP_SLAB_EXACT       2
#define RP_SLAB_SMALL       3

#if (RP_PTR_SIZE == 4)

#define RP_SLAB_PAGE_FREE   0
#define RP_SLAB_PAGE_BUSY   0xffffffff
#define RP_SLAB_PAGE_START  0x80000000

#define RP_SLAB_SHIFT_MASK  0x0000000f
#define RP_SLAB_MAP_MASK    0xffff0000
#define RP_SLAB_MAP_SHIFT   16

#define RP_SLAB_BUSY        0xffffffff

#else /* (RP_PTR_SIZE == 8) */

#define RP_SLAB_PAGE_FREE   0
#define RP_SLAB_PAGE_BUSY   0xffffffffffffffff
#define RP_SLAB_PAGE_START  0x8000000000000000

#define RP_SLAB_SHIFT_MASK  0x000000000000000f
#define RP_SLAB_MAP_MASK    0xffffffff00000000
#define RP_SLAB_MAP_SHIFT   32

#define RP_SLAB_BUSY        0xffffffffffffffff

#endif


#define rp_slab_slots(pool)                                                  \
    (rp_slab_page_t *) ((u_char *) (pool) + sizeof(rp_slab_pool_t))

#define rp_slab_page_type(page)   ((page)->prev & RP_SLAB_PAGE_MASK)

#define rp_slab_page_prev(page)                                              \
    (rp_slab_page_t *) ((page)->prev & ~RP_SLAB_PAGE_MASK)

#define rp_slab_page_addr(pool, page)                                        \
    ((((page) - (pool)->pages) << rp_pagesize_shift)                         \
     + (uintptr_t) (pool)->start)


#if (RP_DEBUG_MALLOC)

#define rp_slab_junk(p, size)     rp_memset(p, 0xA5, size)

#elif (RP_HAVE_DEBUG_MALLOC)

#define rp_slab_junk(p, size)                                                \
    if (rp_debug_malloc)          rp_memset(p, 0xA5, size)

#else

#define rp_slab_junk(p, size)

#endif

static rp_slab_page_t *rp_slab_alloc_pages(rp_slab_pool_t *pool,
    rp_uint_t pages);
static void rp_slab_free_pages(rp_slab_pool_t *pool, rp_slab_page_t *page,
    rp_uint_t pages);
static void rp_slab_error(rp_slab_pool_t *pool, rp_uint_t level,
    char *text);


static rp_uint_t  rp_slab_max_size;
static rp_uint_t  rp_slab_exact_size;
static rp_uint_t  rp_slab_exact_shift;


void
rp_slab_sizes_init(void)
{
    rp_uint_t  n;

    rp_slab_max_size = rp_pagesize / 2;
    rp_slab_exact_size = rp_pagesize / (8 * sizeof(uintptr_t));
    for (n = rp_slab_exact_size; n >>= 1; rp_slab_exact_shift++) {
        /* void */
    }
}


void
rp_slab_init(rp_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    rp_int_t         m;
    rp_uint_t        i, n, pages;
    rp_slab_page_t  *slots, *page;

    pool->min_size = (size_t) 1 << pool->min_shift;

    slots = rp_slab_slots(pool);

    p = (u_char *) slots;
    size = pool->end - p;

    rp_slab_junk(p, size);

    n = rp_pagesize_shift - pool->min_shift;

    for (i = 0; i < n; i++) {
        /* only "next" is used in list head */
        slots[i].slab = 0;
        slots[i].next = &slots[i];
        slots[i].prev = 0;
    }

    p += n * sizeof(rp_slab_page_t);

    pool->stats = (rp_slab_stat_t *) p;
    rp_memzero(pool->stats, n * sizeof(rp_slab_stat_t));

    p += n * sizeof(rp_slab_stat_t);

    size -= n * (sizeof(rp_slab_page_t) + sizeof(rp_slab_stat_t));

    pages = (rp_uint_t) (size / (rp_pagesize + sizeof(rp_slab_page_t)));

    pool->pages = (rp_slab_page_t *) p;
    rp_memzero(pool->pages, pages * sizeof(rp_slab_page_t));

    page = pool->pages;

    /* only "next" is used in list head */
    pool->free.slab = 0;
    pool->free.next = page;
    pool->free.prev = 0;

    page->slab = pages;
    page->next = &pool->free;
    page->prev = (uintptr_t) &pool->free;

    pool->start = rp_align_ptr(p + pages * sizeof(rp_slab_page_t),
                                rp_pagesize);

    m = pages - (pool->end - pool->start) / rp_pagesize;
    if (m > 0) {
        pages -= m;
        page->slab = pages;
    }

    pool->last = pool->pages + pages;
    pool->pfree = pages;

    pool->log_nomem = 1;
    pool->log_ctx = &pool->zero;
    pool->zero = '\0';
}


void *
rp_slab_alloc(rp_slab_pool_t *pool, size_t size)
{
    void  *p;

    rp_shmtx_lock(&pool->mutex);

    p = rp_slab_alloc_locked(pool, size);

    rp_shmtx_unlock(&pool->mutex);

    return p;
}


void *
rp_slab_alloc_locked(rp_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, m, mask, *bitmap;
    rp_uint_t        i, n, slot, shift, map;
    rp_slab_page_t  *page, *prev, *slots;

    if (size > rp_slab_max_size) {

        rp_log_debug1(RP_LOG_DEBUG_ALLOC, rp_cycle->log, 0,
                       "slab alloc: %uz", size);

        page = rp_slab_alloc_pages(pool, (size >> rp_pagesize_shift)
                                          + ((size % rp_pagesize) ? 1 : 0));
        if (page) {
            p = rp_slab_page_addr(pool, page);

        } else {
            p = 0;
        }

        goto done;
    }

    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
        slot = shift - pool->min_shift;

    } else {
        shift = pool->min_shift;
        slot = 0;
    }

    pool->stats[slot].reqs++;

    rp_log_debug2(RP_LOG_DEBUG_ALLOC, rp_cycle->log, 0,
                   "slab alloc: %uz slot: %ui", size, slot);

    slots = rp_slab_slots(pool);
    page = slots[slot].next;

    if (page->next != page) {

        if (shift < rp_slab_exact_shift) {

            bitmap = (uintptr_t *) rp_slab_page_addr(pool, page);

            map = (rp_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (n = 0; n < map; n++) {

                if (bitmap[n] != RP_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if (bitmap[n] & m) {
                            continue;
                        }

                        bitmap[n] |= m;

                        i = (n * 8 * sizeof(uintptr_t) + i) << shift;

                        p = (uintptr_t) bitmap + i;

                        pool->stats[slot].used++;

                        if (bitmap[n] == RP_SLAB_BUSY) {
                            for (n = n + 1; n < map; n++) {
                                if (bitmap[n] != RP_SLAB_BUSY) {
                                    goto done;
                                }
                            }

                            prev = rp_slab_page_prev(page);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = RP_SLAB_SMALL;
                        }

                        goto done;
                    }
                }
            }

        } else if (shift == rp_slab_exact_shift) {

            for (m = 1, i = 0; m; m <<= 1, i++) {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if (page->slab == RP_SLAB_BUSY) {
                    prev = rp_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = RP_SLAB_EXACT;
                }

                p = rp_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }

        } else { /* shift > rp_slab_exact_shift */

            mask = ((uintptr_t) 1 << (rp_pagesize >> shift)) - 1;
            mask <<= RP_SLAB_MAP_SHIFT;

            for (m = (uintptr_t) 1 << RP_SLAB_MAP_SHIFT, i = 0;
                 m & mask;
                 m <<= 1, i++)
            {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if ((page->slab & RP_SLAB_MAP_MASK) == mask) {
                    prev = rp_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = RP_SLAB_BIG;
                }

                p = rp_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }
        }

        rp_slab_error(pool, RP_LOG_ALERT, "rp_slab_alloc(): page is busy");
        rp_debug_point();
    }

    page = rp_slab_alloc_pages(pool, 1);

    if (page) {
        if (shift < rp_slab_exact_shift) {
            bitmap = (uintptr_t *) rp_slab_page_addr(pool, page);

            n = (rp_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            /* "n" elements for bitmap, plus one requested */

            for (i = 0; i < (n + 1) / (8 * sizeof(uintptr_t)); i++) {
                bitmap[i] = RP_SLAB_BUSY;
            }

            m = ((uintptr_t) 1 << ((n + 1) % (8 * sizeof(uintptr_t)))) - 1;
            bitmap[i] = m;

            map = (rp_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                bitmap[i] = 0;
            }

            page->slab = shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | RP_SLAB_SMALL;

            slots[slot].next = page;

            pool->stats[slot].total += (rp_pagesize >> shift) - n;

            p = rp_slab_page_addr(pool, page) + (n << shift);

            pool->stats[slot].used++;

            goto done;

        } else if (shift == rp_slab_exact_shift) {

            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | RP_SLAB_EXACT;

            slots[slot].next = page;

            pool->stats[slot].total += 8 * sizeof(uintptr_t);

            p = rp_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;

        } else { /* shift > rp_slab_exact_shift */

            page->slab = ((uintptr_t) 1 << RP_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | RP_SLAB_BIG;

            slots[slot].next = page;

            pool->stats[slot].total += rp_pagesize >> shift;

            p = rp_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;
        }
    }

    p = 0;

    pool->stats[slot].fails++;

done:

    rp_log_debug1(RP_LOG_DEBUG_ALLOC, rp_cycle->log, 0,
                   "slab alloc: %p", (void *) p);

    return (void *) p;
}


void *
rp_slab_calloc(rp_slab_pool_t *pool, size_t size)
{
    void  *p;

    rp_shmtx_lock(&pool->mutex);

    p = rp_slab_calloc_locked(pool, size);

    rp_shmtx_unlock(&pool->mutex);

    return p;
}


void *
rp_slab_calloc_locked(rp_slab_pool_t *pool, size_t size)
{
    void  *p;

    p = rp_slab_alloc_locked(pool, size);
    if (p) {
        rp_memzero(p, size);
    }

    return p;
}


void
rp_slab_free(rp_slab_pool_t *pool, void *p)
{
    rp_shmtx_lock(&pool->mutex);

    rp_slab_free_locked(pool, p);

    rp_shmtx_unlock(&pool->mutex);
}


void
rp_slab_free_locked(rp_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    rp_uint_t        i, n, type, slot, shift, map;
    rp_slab_page_t  *slots, *page;

    rp_log_debug1(RP_LOG_DEBUG_ALLOC, rp_cycle->log, 0, "slab free: %p", p);

    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        rp_slab_error(pool, RP_LOG_ALERT, "rp_slab_free(): outside of pool");
        goto fail;
    }

    n = ((u_char *) p - pool->start) >> rp_pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
    type = rp_slab_page_type(page);

    switch (type) {

    case RP_SLAB_SMALL:

        shift = slab & RP_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (rp_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)));
        n /= 8 * sizeof(uintptr_t);
        bitmap = (uintptr_t *)
                             ((uintptr_t) p & ~((uintptr_t) rp_pagesize - 1));

        if (bitmap[n] & m) {
            slot = shift - pool->min_shift;

            if (page->next == NULL) {
                slots = rp_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | RP_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | RP_SLAB_SMALL;
            }

            bitmap[n] &= ~m;

            n = (rp_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            i = n / (8 * sizeof(uintptr_t));
            m = ((uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)))) - 1;

            if (bitmap[i] & ~m) {
                goto done;
            }

            map = (rp_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                if (bitmap[i]) {
                    goto done;
                }
            }

            rp_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= (rp_pagesize >> shift) - n;

            goto done;
        }

        goto chunk_already_free;

    case RP_SLAB_EXACT:

        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (rp_pagesize - 1)) >> rp_slab_exact_shift);
        size = rp_slab_exact_size;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            slot = rp_slab_exact_shift - pool->min_shift;

            if (slab == RP_SLAB_BUSY) {
                slots = rp_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | RP_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | RP_SLAB_EXACT;
            }

            page->slab &= ~m;

            if (page->slab) {
                goto done;
            }

            rp_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= 8 * sizeof(uintptr_t);

            goto done;
        }

        goto chunk_already_free;

    case RP_SLAB_BIG:

        shift = slab & RP_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (rp_pagesize - 1)) >> shift)
                              + RP_SLAB_MAP_SHIFT);

        if (slab & m) {
            slot = shift - pool->min_shift;

            if (page->next == NULL) {
                slots = rp_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | RP_SLAB_BIG;
                page->next->prev = (uintptr_t) page | RP_SLAB_BIG;
            }

            page->slab &= ~m;

            if (page->slab & RP_SLAB_MAP_MASK) {
                goto done;
            }

            rp_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= rp_pagesize >> shift;

            goto done;
        }

        goto chunk_already_free;

    case RP_SLAB_PAGE:

        if ((uintptr_t) p & (rp_pagesize - 1)) {
            goto wrong_chunk;
        }

        if (!(slab & RP_SLAB_PAGE_START)) {
            rp_slab_error(pool, RP_LOG_ALERT,
                           "rp_slab_free(): page is already free");
            goto fail;
        }

        if (slab == RP_SLAB_PAGE_BUSY) {
            rp_slab_error(pool, RP_LOG_ALERT,
                           "rp_slab_free(): pointer to wrong page");
            goto fail;
        }

        size = slab & ~RP_SLAB_PAGE_START;

        rp_slab_free_pages(pool, page, size);

        rp_slab_junk(p, size << rp_pagesize_shift);

        return;
    }

    /* not reached */

    return;

done:

    pool->stats[slot].used--;

    rp_slab_junk(p, size);

    return;

wrong_chunk:

    rp_slab_error(pool, RP_LOG_ALERT,
                   "rp_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    rp_slab_error(pool, RP_LOG_ALERT,
                   "rp_slab_free(): chunk is already free");

fail:

    return;
}


static rp_slab_page_t *
rp_slab_alloc_pages(rp_slab_pool_t *pool, rp_uint_t pages)
{
    rp_slab_page_t  *page, *p;

    for (page = pool->free.next; page != &pool->free; page = page->next) {

        if (page->slab >= pages) {

            if (page->slab > pages) {
                page[page->slab - 1].prev = (uintptr_t) &page[pages];

                page[pages].slab = page->slab - pages;
                page[pages].next = page->next;
                page[pages].prev = page->prev;

                p = (rp_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {
                p = (rp_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

            page->slab = pages | RP_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = RP_SLAB_PAGE;

            pool->pfree -= pages;

            if (--pages == 0) {
                return page;
            }

            for (p = page + 1; pages; pages--) {
                p->slab = RP_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = RP_SLAB_PAGE;
                p++;
            }

            return page;
        }
    }

    if (pool->log_nomem) {
        rp_slab_error(pool, RP_LOG_CRIT,
                       "rp_slab_alloc() failed: no memory");
    }

    return NULL;
}


static void
rp_slab_free_pages(rp_slab_pool_t *pool, rp_slab_page_t *page,
    rp_uint_t pages)
{
    rp_slab_page_t  *prev, *join;

    pool->pfree += pages;

    page->slab = pages--;

    if (pages) {
        rp_memzero(&page[1], pages * sizeof(rp_slab_page_t));
    }

    if (page->next) {
        prev = rp_slab_page_prev(page);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    join = page + page->slab;

    if (join < pool->last) {

        if (rp_slab_page_type(join) == RP_SLAB_PAGE) {

            if (join->next != NULL) {
                pages += join->slab;
                page->slab += join->slab;

                prev = rp_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                join->slab = RP_SLAB_PAGE_FREE;
                join->next = NULL;
                join->prev = RP_SLAB_PAGE;
            }
        }
    }

    if (page > pool->pages) {
        join = page - 1;

        if (rp_slab_page_type(join) == RP_SLAB_PAGE) {

            if (join->slab == RP_SLAB_PAGE_FREE) {
                join = rp_slab_page_prev(join);
            }

            if (join->next != NULL) {
                pages += join->slab;
                join->slab += page->slab;

                prev = rp_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                page->slab = RP_SLAB_PAGE_FREE;
                page->next = NULL;
                page->prev = RP_SLAB_PAGE;

                page = join;
            }
        }
    }

    if (pages) {
        page[pages].prev = (uintptr_t) page;
    }

    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    pool->free.next = page;
}


static void
rp_slab_error(rp_slab_pool_t *pool, rp_uint_t level, char *text)
{
    rp_log_error(level, rp_cycle->log, 0, "%s%s", text, pool->log_ctx);
}
