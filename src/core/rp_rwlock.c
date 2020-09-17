
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#if (RP_HAVE_ATOMIC_OPS)


#define RP_RWLOCK_SPIN   2048
#define RP_RWLOCK_WLOCK  ((rp_atomic_uint_t) -1)


void
rp_rwlock_wlock(rp_atomic_t *lock)
{
    rp_uint_t  i, n;

    for ( ;; ) {

        if (*lock == 0 && rp_atomic_cmp_set(lock, 0, RP_RWLOCK_WLOCK)) {
            return;
        }

        if (rp_ncpu > 1) {

            for (n = 1; n < RP_RWLOCK_SPIN; n <<= 1) {

                for (i = 0; i < n; i++) {
                    rp_cpu_pause();
                }

                if (*lock == 0
                    && rp_atomic_cmp_set(lock, 0, RP_RWLOCK_WLOCK))
                {
                    return;
                }
            }
        }

        rp_sched_yield();
    }
}


void
rp_rwlock_rlock(rp_atomic_t *lock)
{
    rp_uint_t         i, n;
    rp_atomic_uint_t  readers;

    for ( ;; ) {
        readers = *lock;

        if (readers != RP_RWLOCK_WLOCK
            && rp_atomic_cmp_set(lock, readers, readers + 1))
        {
            return;
        }

        if (rp_ncpu > 1) {

            for (n = 1; n < RP_RWLOCK_SPIN; n <<= 1) {

                for (i = 0; i < n; i++) {
                    rp_cpu_pause();
                }

                readers = *lock;

                if (readers != RP_RWLOCK_WLOCK
                    && rp_atomic_cmp_set(lock, readers, readers + 1))
                {
                    return;
                }
            }
        }

        rp_sched_yield();
    }
}


void
rp_rwlock_unlock(rp_atomic_t *lock)
{
    rp_atomic_uint_t  readers;

    readers = *lock;

    if (readers == RP_RWLOCK_WLOCK) {
        (void) rp_atomic_cmp_set(lock, RP_RWLOCK_WLOCK, 0);
        return;
    }

    for ( ;; ) {

        if (rp_atomic_cmp_set(lock, readers, readers - 1)) {
            return;
        }

        readers = *lock;
    }
}


void
rp_rwlock_downgrade(rp_atomic_t *lock)
{
    if (*lock == RP_RWLOCK_WLOCK) {
        *lock = 1;
    }
}


#else

#if (RP_HTTP_UPSTREAM_ZONE || RP_STREAM_UPSTREAM_ZONE)

#error rp_atomic_cmp_set() is not defined!

#endif

#endif
