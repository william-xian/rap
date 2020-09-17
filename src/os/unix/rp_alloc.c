
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


rp_uint_t  rp_pagesize;
rp_uint_t  rp_pagesize_shift;
rp_uint_t  rp_cacheline_size;


void *
rp_alloc(size_t size, rp_log_t *log)
{
    void  *p;

    p = malloc(size);
    if (p == NULL) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno,
                      "malloc(%uz) failed", size);
    }

    rp_log_debug2(RP_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);

    return p;
}


void *
rp_calloc(size_t size, rp_log_t *log)
{
    void  *p;

    p = rp_alloc(size, log);

    if (p) {
        rp_memzero(p, size);
    }

    return p;
}


#if (RP_HAVE_POSIX_MEMALIGN)

void *
rp_memalign(size_t alignment, size_t size, rp_log_t *log)
{
    void  *p;
    int    err;

    err = posix_memalign(&p, alignment, size);

    if (err) {
        rp_log_error(RP_LOG_EMERG, log, err,
                      "posix_memalign(%uz, %uz) failed", alignment, size);
        p = NULL;
    }

    rp_log_debug3(RP_LOG_DEBUG_ALLOC, log, 0,
                   "posix_memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#elif (RP_HAVE_MEMALIGN)

void *
rp_memalign(size_t alignment, size_t size, rp_log_t *log)
{
    void  *p;

    p = memalign(alignment, size);
    if (p == NULL) {
        rp_log_error(RP_LOG_EMERG, log, rp_errno,
                      "memalign(%uz, %uz) failed", alignment, size);
    }

    rp_log_debug3(RP_LOG_DEBUG_ALLOC, log, 0,
                   "memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#endif
