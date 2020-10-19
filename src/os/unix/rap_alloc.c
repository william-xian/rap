
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


rap_uint_t  rap_pagesize;
rap_uint_t  rap_pagesize_shift;
rap_uint_t  rap_cacheline_size;


void *
rap_alloc(size_t size, rap_log_t *log)
{
    void  *p;

    p = malloc(size);
    if (p == NULL) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                      "malloc(%uz) failed", size);
    }

    rap_log_debug2(RAP_LOG_DEBUG_ALLOC, log, 0, "malloc: %p:%uz", p, size);

    return p;
}


void *
rap_calloc(size_t size, rap_log_t *log)
{
    void  *p;

    p = rap_alloc(size, log);

    if (p) {
        rap_memzero(p, size);
    }

    return p;
}


#if (RAP_HAVE_POSIX_MEMALIGN)

void *
rap_memalign(size_t alignment, size_t size, rap_log_t *log)
{
    void  *p;
    int    err;

    err = posix_memalign(&p, alignment, size);

    if (err) {
        rap_log_error(RAP_LOG_EMERG, log, err,
                      "posix_memalign(%uz, %uz) failed", alignment, size);
        p = NULL;
    }

    rap_log_debug3(RAP_LOG_DEBUG_ALLOC, log, 0,
                   "posix_memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#elif (RAP_HAVE_MEMALIGN)

void *
rap_memalign(size_t alignment, size_t size, rap_log_t *log)
{
    void  *p;

    p = memalign(alignment, size);
    if (p == NULL) {
        rap_log_error(RAP_LOG_EMERG, log, rap_errno,
                      "memalign(%uz, %uz) failed", alignment, size);
    }

    rap_log_debug3(RAP_LOG_DEBUG_ALLOC, log, 0,
                   "memalign: %p:%uz @%uz", p, size, alignment);

    return p;
}

#endif
