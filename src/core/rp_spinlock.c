
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


void
rp_spinlock(rp_atomic_t *lock, rp_atomic_int_t value, rp_uint_t spin)
{

#if (RP_HAVE_ATOMIC_OPS)

    rp_uint_t  i, n;

    for ( ;; ) {

        if (*lock == 0 && rp_atomic_cmp_set(lock, 0, value)) {
            return;
        }

        if (rp_ncpu > 1) {

            for (n = 1; n < spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    rp_cpu_pause();
                }

                if (*lock == 0 && rp_atomic_cmp_set(lock, 0, value)) {
                    return;
                }
            }
        }

        rp_sched_yield();
    }

#else

#if (RP_THREADS)

#error rp_spinlock() or rp_atomic_cmp_set() are not defined !

#endif

#endif

}
