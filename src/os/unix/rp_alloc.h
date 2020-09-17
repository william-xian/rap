
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_ALLOC_H_INCLUDED_
#define _RP_ALLOC_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


void *rp_alloc(size_t size, rp_log_t *log);
void *rp_calloc(size_t size, rp_log_t *log);

#define rp_free          free


/*
 * Linux has memalign() or posix_memalign()
 * Solaris has memalign()
 * FreeBSD 7.0 has posix_memalign(), besides, early version's malloc()
 * aligns allocations bigger than page size at the page boundary
 */

#if (RP_HAVE_POSIX_MEMALIGN || RP_HAVE_MEMALIGN)

void *rp_memalign(size_t alignment, size_t size, rp_log_t *log);

#else

#define rp_memalign(alignment, size, log)  rp_alloc(size, log)

#endif


extern rp_uint_t  rp_pagesize;
extern rp_uint_t  rp_pagesize_shift;
extern rp_uint_t  rp_cacheline_size;


#endif /* _RP_ALLOC_H_INCLUDED_ */
