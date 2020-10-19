
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_ALLOC_H_INCLUDED_
#define _RAP_ALLOC_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


void *rap_alloc(size_t size, rap_log_t *log);
void *rap_calloc(size_t size, rap_log_t *log);

#define rap_free          free


/*
 * Linux has memalign() or posix_memalign()
 * Solaris has memalign()
 * FreeBSD 7.0 has posix_memalign(), besides, early version's malloc()
 * aligns allocations bigger than page size at the page boundary
 */

#if (RAP_HAVE_POSIX_MEMALIGN || RAP_HAVE_MEMALIGN)

void *rap_memalign(size_t alignment, size_t size, rap_log_t *log);

#else

#define rap_memalign(alignment, size, log)  rap_alloc(size, log)

#endif


extern rap_uint_t  rap_pagesize;
extern rap_uint_t  rap_pagesize_shift;
extern rap_uint_t  rap_cacheline_size;


#endif /* _RAP_ALLOC_H_INCLUDED_ */
