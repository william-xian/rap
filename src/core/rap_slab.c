
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */

#include <rap_config.h>
#include <rap_core.h>


#define RAP_SLAB_PAGE_MASK   3
#define RAP_SLAB_PAGE        0
#define RAP_SLAB_BIG         1
#define RAP_SLAB_EXACT       2
#define RAP_SLAB_SMALL       3

#if (RAP_PTR_SIZE == 4)

#define RAP_SLAB_PAGE_FREE   0
#define RAP_SLAB_PAGE_BUSY   0xffffffff
#define RAP_SLAB_PAGE_START  0x80000000

#define RAP_SLAB_SHIFT_MASK  0x0000000f
#define RAP_SLAB_MAP_MASK    0xffff0000
#define RAP_SLAB_MAP_SHIFT   16

#define RAP_SLAB_BUSY        0xffffffff

#else /* (RAP_PTR_SIZE == 8) */

#define RAP_SLAB_PAGE_FREE   0
#define RAP_SLAB_PAGE_BUSY   0xffffffffffffffff
#define RAP_SLAB_PAGE_START  0x8000000000000000

#define RAP_SLAB_SHIFT_MASK  0x000000000000000f
#define RAP_SLAB_MAP_MASK    0xffffffff00000000
#define RAP_SLAB_MAP_SHIFT   32

#define RAP_SLAB_BUSY        0xffffffffffffffff

#endif


#define rap_slab_slots(pool)                                                  \
    (rap_slab_page_t *) ((u_char *) (pool) + sizeof(rap_slab_pool_t))

#define rap_slab_page_type(page)   ((page)->prev & RAP_SLAB_PAGE_MASK)

#define rap_slab_page_prev(page)                                              \
    (rap_slab_page_t *) ((page)->prev & ~RAP_SLAB_PAGE_MASK)

#define rap_slab_page_addr(pool, page)                                        \
    ((((page) - (pool)->pages) << rap_pagesize_shift)                         \
     + (uintptr_t) (pool)->start)


#if (RAP_DEBUG_MALLOC)

#define rap_slab_junk(p, size)     rap_memset(p, 0xA5, size)

#elif (RAP_HAVE_DEBUG_MALLOC)

#define rap_slab_junk(p, size)                                                \
    if (rap_debug_malloc)          rap_memset(p, 0xA5, size)

#else

#define rap_slab_junk(p, size)

#endif

static rap_slab_page_t *rap_slab_alloc_pages(rap_slab_pool_t *pool,
    rap_uint_t pages);
static void rap_slab_free_pages(rap_slab_pool_t *pool, rap_slab_page_t *page,
    rap_uint_t pages);
static void rap_slab_error(rap_slab_pool_t *pool, rap_uint_t level,
    char *text);


static rap_uint_t  rap_slab_max_size;
static rap_uint_t  rap_slab_exact_size;
static rap_uint_t  rap_slab_exact_shift;


void
rap_slab_sizes_init(void)
{
    rap_uint_t  n;

    rap_slab_max_size = rap_pagesize / 2;
    rap_slab_exact_size = rap_pagesize / (8 * sizeof(uintptr_t));
    for (n = rap_slab_exact_size; n >>= 1; rap_slab_exact_shift++) {
        /* void */
    }
}


void
rap_slab_init(rap_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    rap_int_t         m;
    rap_uint_t        i, n, pages;
    rap_slab_page_t  *slots, *page;

    pool->min_size = (size_t) 1 << pool->min_shift;

    slots = rap_slab_slots(pool);

    p = (u_char *) slots;
    size = pool->end - p;

    rap_slab_junk(p, size);

    n = rap_pagesize_shift - pool->min_shift;

    for (i = 0; i < n; i++) {
        /* only "next" is used in list head */
        slots[i].slab = 0;
        slots[i].next = &slots[i];
        slots[i].prev = 0;
    }

    p += n * sizeof(rap_slab_page_t);

    pool->stats = (rap_slab_stat_t *) p;
    rap_memzero(pool->stats, n * sizeof(rap_slab_stat_t));

    p += n * sizeof(rap_slab_stat_t);

    size -= n * (sizeof(rap_slab_page_t) + sizeof(rap_slab_stat_t));

    pages = (rap_uint_t) (size / (rap_pagesize + sizeof(rap_slab_page_t)));

    pool->pages = (rap_slab_page_t *) p;
    rap_memzero(pool->pages, pages * sizeof(rap_slab_page_t));

    page = pool->pages;

    /* only "next" is used in list head */
    pool->free.slab = 0;
    pool->free.next = page;
    pool->free.prev = 0;

    page->slab = pages;
    page->next = &pool->free;
    page->prev = (uintptr_t) &pool->free;

    pool->start = rap_align_ptr(p + pages * sizeof(rap_slab_page_t),
                                rap_pagesize);

    m = pages - (pool->end - pool->start) / rap_pagesize;
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
rap_slab_alloc(rap_slab_pool_t *pool, size_t size)
{
    void  *p;

    rap_shmtx_lock(&pool->mutex);

    p = rap_slab_alloc_locked(pool, size);

    rap_shmtx_unlock(&pool->mutex);

    return p;
}


void *
rap_slab_alloc_locked(rap_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, m, mask, *bitmap;
    rap_uint_t        i, n, slot, shift, map;
    rap_slab_page_t  *page, *prev, *slots;

    if (size > rap_slab_max_size) {

        rap_log_debug1(RAP_LOG_DEBUG_ALLOC, rap_cycle->log, 0,
                       "slab alloc: %uz", size);

        page = rap_slab_alloc_pages(pool, (size >> rap_pagesize_shift)
                                          + ((size % rap_pagesize) ? 1 : 0));
        if (page) {
            p = rap_slab_page_addr(pool, page);

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

    rap_log_debug2(RAP_LOG_DEBUG_ALLOC, rap_cycle->log, 0,
                   "slab alloc: %uz slot: %ui", size, slot);

    slots = rap_slab_slots(pool);
    page = slots[slot].next;

    if (page->next != page) {

        if (shift < rap_slab_exact_shift) {

            bitmap = (uintptr_t *) rap_slab_page_addr(pool, page);

            map = (rap_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (n = 0; n < map; n++) {

                if (bitmap[n] != RAP_SLAB_BUSY) {

                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if (bitmap[n] & m) {
                            continue;
                        }

                        bitmap[n] |= m;

                        i = (n * 8 * sizeof(uintptr_t) + i) << shift;

                        p = (uintptr_t) bitmap + i;

                        pool->stats[slot].used++;

                        if (bitmap[n] == RAP_SLAB_BUSY) {
                            for (n = n + 1; n < map; n++) {
                                if (bitmap[n] != RAP_SLAB_BUSY) {
                                    goto done;
                                }
                            }

                            prev = rap_slab_page_prev(page);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = RAP_SLAB_SMALL;
                        }

                        goto done;
                    }
                }
            }

        } else if (shift == rap_slab_exact_shift) {

            for (m = 1, i = 0; m; m <<= 1, i++) {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if (page->slab == RAP_SLAB_BUSY) {
                    prev = rap_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = RAP_SLAB_EXACT;
                }

                p = rap_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }

        } else { /* shift > rap_slab_exact_shift */

            mask = ((uintptr_t) 1 << (rap_pagesize >> shift)) - 1;
            mask <<= RAP_SLAB_MAP_SHIFT;

            for (m = (uintptr_t) 1 << RAP_SLAB_MAP_SHIFT, i = 0;
                 m & mask;
                 m <<= 1, i++)
            {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if ((page->slab & RAP_SLAB_MAP_MASK) == mask) {
                    prev = rap_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = RAP_SLAB_BIG;
                }

                p = rap_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }
        }

        rap_slab_error(pool, RAP_LOG_ALERT, "rap_slab_alloc(): page is busy");
        rap_debug_point();
    }

    page = rap_slab_alloc_pages(pool, 1);

    if (page) {
        if (shift < rap_slab_exact_shift) {
            bitmap = (uintptr_t *) rap_slab_page_addr(pool, page);

            n = (rap_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            /* "n" elements for bitmap, plus one requested */

            for (i = 0; i < (n + 1) / (8 * sizeof(uintptr_t)); i++) {
                bitmap[i] = RAP_SLAB_BUSY;
            }

            m = ((uintptr_t) 1 << ((n + 1) % (8 * sizeof(uintptr_t)))) - 1;
            bitmap[i] = m;

            map = (rap_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                bitmap[i] = 0;
            }

            page->slab = shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | RAP_SLAB_SMALL;

            slots[slot].next = page;

            pool->stats[slot].total += (rap_pagesize >> shift) - n;

            p = rap_slab_page_addr(pool, page) + (n << shift);

            pool->stats[slot].used++;

            goto done;

        } else if (shift == rap_slab_exact_shift) {

            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | RAP_SLAB_EXACT;

            slots[slot].next = page;

            pool->stats[slot].total += 8 * sizeof(uintptr_t);

            p = rap_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;

        } else { /* shift > rap_slab_exact_shift */

            page->slab = ((uintptr_t) 1 << RAP_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | RAP_SLAB_BIG;

            slots[slot].next = page;

            pool->stats[slot].total += rap_pagesize >> shift;

            p = rap_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;
        }
    }

    p = 0;

    pool->stats[slot].fails++;

done:

    rap_log_debug1(RAP_LOG_DEBUG_ALLOC, rap_cycle->log, 0,
                   "slab alloc: %p", (void *) p);

    return (void *) p;
}


void *
rap_slab_calloc(rap_slab_pool_t *pool, size_t size)
{
    void  *p;

    rap_shmtx_lock(&pool->mutex);

    p = rap_slab_calloc_locked(pool, size);

    rap_shmtx_unlock(&pool->mutex);

    return p;
}


void *
rap_slab_calloc_locked(rap_slab_pool_t *pool, size_t size)
{
    void  *p;

    p = rap_slab_alloc_locked(pool, size);
    if (p) {
        rap_memzero(p, size);
    }

    return p;
}


void
rap_slab_free(rap_slab_pool_t *pool, void *p)
{
    rap_shmtx_lock(&pool->mutex);

    rap_slab_free_locked(pool, p);

    rap_shmtx_unlock(&pool->mutex);
}


void
rap_slab_free_locked(rap_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    rap_uint_t        i, n, type, slot, shift, map;
    rap_slab_page_t  *slots, *page;

    rap_log_debug1(RAP_LOG_DEBUG_ALLOC, rap_cycle->log, 0, "slab free: %p", p);

    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        rap_slab_error(pool, RAP_LOG_ALERT, "rap_slab_free(): outside of pool");
        goto fail;
    }

    n = ((u_char *) p - pool->start) >> rap_pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
    type = rap_slab_page_type(page);

    switch (type) {

    case RAP_SLAB_SMALL:

        shift = slab & RAP_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        n = ((uintptr_t) p & (rap_pagesize - 1)) >> shift;
        m = (uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)));
        n /= 8 * sizeof(uintptr_t);
        bitmap = (uintptr_t *)
                             ((uintptr_t) p & ~((uintptr_t) rap_pagesize - 1));

        if (bitmap[n] & m) {
            slot = shift - pool->min_shift;

            if (page->next == NULL) {
                slots = rap_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | RAP_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | RAP_SLAB_SMALL;
            }

            bitmap[n] &= ~m;

            n = (rap_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            i = n / (8 * sizeof(uintptr_t));
            m = ((uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)))) - 1;

            if (bitmap[i] & ~m) {
                goto done;
            }

            map = (rap_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                if (bitmap[i]) {
                    goto done;
                }
            }

            rap_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= (rap_pagesize >> shift) - n;

            goto done;
        }

        goto chunk_already_free;

    case RAP_SLAB_EXACT:

        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (rap_pagesize - 1)) >> rap_slab_exact_shift);
        size = rap_slab_exact_size;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            slot = rap_slab_exact_shift - pool->min_shift;

            if (slab == RAP_SLAB_BUSY) {
                slots = rap_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | RAP_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | RAP_SLAB_EXACT;
            }

            page->slab &= ~m;

            if (page->slab) {
                goto done;
            }

            rap_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= 8 * sizeof(uintptr_t);

            goto done;
        }

        goto chunk_already_free;

    case RAP_SLAB_BIG:

        shift = slab & RAP_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (rap_pagesize - 1)) >> shift)
                              + RAP_SLAB_MAP_SHIFT);

        if (slab & m) {
            slot = shift - pool->min_shift;

            if (page->next == NULL) {
                slots = rap_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | RAP_SLAB_BIG;
                page->next->prev = (uintptr_t) page | RAP_SLAB_BIG;
            }

            page->slab &= ~m;

            if (page->slab & RAP_SLAB_MAP_MASK) {
                goto done;
            }

            rap_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= rap_pagesize >> shift;

            goto done;
        }

        goto chunk_already_free;

    case RAP_SLAB_PAGE:

        if ((uintptr_t) p & (rap_pagesize - 1)) {
            goto wrong_chunk;
        }

        if (!(slab & RAP_SLAB_PAGE_START)) {
            rap_slab_error(pool, RAP_LOG_ALERT,
                           "rap_slab_free(): page is already free");
            goto fail;
        }

        if (slab == RAP_SLAB_PAGE_BUSY) {
            rap_slab_error(pool, RAP_LOG_ALERT,
                           "rap_slab_free(): pointer to wrong page");
            goto fail;
        }

        size = slab & ~RAP_SLAB_PAGE_START;

        rap_slab_free_pages(pool, page, size);

        rap_slab_junk(p, size << rap_pagesize_shift);

        return;
    }

    /* not reached */

    return;

done:

    pool->stats[slot].used--;

    rap_slab_junk(p, size);

    return;

wrong_chunk:

    rap_slab_error(pool, RAP_LOG_ALERT,
                   "rap_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    rap_slab_error(pool, RAP_LOG_ALERT,
                   "rap_slab_free(): chunk is already free");

fail:

    return;
}


static rap_slab_page_t *
rap_slab_alloc_pages(rap_slab_pool_t *pool, rap_uint_t pages)
{
    rap_slab_page_t  *page, *p;

    for (page = pool->free.next; page != &pool->free; page = page->next) {

        if (page->slab >= pages) {

            if (page->slab > pages) {
                page[page->slab - 1].prev = (uintptr_t) &page[pages];

                page[pages].slab = page->slab - pages;
                page[pages].next = page->next;
                page[pages].prev = page->prev;

                p = (rap_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {
                p = (rap_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }

            page->slab = pages | RAP_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = RAP_SLAB_PAGE;

            pool->pfree -= pages;

            if (--pages == 0) {
                return page;
            }

            for (p = page + 1; pages; pages--) {
                p->slab = RAP_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = RAP_SLAB_PAGE;
                p++;
            }

            return page;
        }
    }

    if (pool->log_nomem) {
        rap_slab_error(pool, RAP_LOG_CRIT,
                       "rap_slab_alloc() failed: no memory");
    }

    return NULL;
}


static void
rap_slab_free_pages(rap_slab_pool_t *pool, rap_slab_page_t *page,
    rap_uint_t pages)
{
    rap_slab_page_t  *prev, *join;

    pool->pfree += pages;

    page->slab = pages--;

    if (pages) {
        rap_memzero(&page[1], pages * sizeof(rap_slab_page_t));
    }

    if (page->next) {
        prev = rap_slab_page_prev(page);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    join = page + page->slab;

    if (join < pool->last) {

        if (rap_slab_page_type(join) == RAP_SLAB_PAGE) {

            if (join->next != NULL) {
                pages += join->slab;
                page->slab += join->slab;

                prev = rap_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                join->slab = RAP_SLAB_PAGE_FREE;
                join->next = NULL;
                join->prev = RAP_SLAB_PAGE;
            }
        }
    }

    if (page > pool->pages) {
        join = page - 1;

        if (rap_slab_page_type(join) == RAP_SLAB_PAGE) {

            if (join->slab == RAP_SLAB_PAGE_FREE) {
                join = rap_slab_page_prev(join);
            }

            if (join->next != NULL) {
                pages += join->slab;
                join->slab += page->slab;

                prev = rap_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                page->slab = RAP_SLAB_PAGE_FREE;
                page->next = NULL;
                page->prev = RAP_SLAB_PAGE;

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
rap_slab_error(rap_slab_pool_t *pool, rap_uint_t level, char *text)
{
    rap_log_error(level, rap_cycle->log, 0, "%s%s", text, pool->log_ctx);
}
