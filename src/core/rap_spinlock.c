
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


void
rap_spinlock(rap_atomic_t *lock, rap_atomic_int_t value, rap_uint_t spin)
{

#if (RAP_HAVE_ATOMIC_OPS)

    rap_uint_t  i, n;

    for ( ;; ) {

        if (*lock == 0 && rap_atomic_cmp_set(lock, 0, value)) {
            return;
        }

        if (rap_ncpu > 1) {

            for (n = 1; n < spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    rap_cpu_pause();
                }

                if (*lock == 0 && rap_atomic_cmp_set(lock, 0, value)) {
                    return;
                }
            }
        }

        rap_sched_yield();
    }

#else

#if (RAP_THREADS)

#error rap_spinlock() or rap_atomic_cmp_set() are not defined !

#endif

#endif

}
