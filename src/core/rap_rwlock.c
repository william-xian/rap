
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#if (RAP_HAVE_ATOMIC_OPS)


#define RAP_RWLOCK_SPIN   2048
#define RAP_RWLOCK_WLOCK  ((rap_atomic_uint_t) -1)


void
rap_rwlock_wlock(rap_atomic_t *lock)
{
    rap_uint_t  i, n;

    for ( ;; ) {

        if (*lock == 0 && rap_atomic_cmp_set(lock, 0, RAP_RWLOCK_WLOCK)) {
            return;
        }

        if (rap_ncpu > 1) {

            for (n = 1; n < RAP_RWLOCK_SPIN; n <<= 1) {

                for (i = 0; i < n; i++) {
                    rap_cpu_pause();
                }

                if (*lock == 0
                    && rap_atomic_cmp_set(lock, 0, RAP_RWLOCK_WLOCK))
                {
                    return;
                }
            }
        }

        rap_sched_yield();
    }
}


void
rap_rwlock_rlock(rap_atomic_t *lock)
{
    rap_uint_t         i, n;
    rap_atomic_uint_t  readers;

    for ( ;; ) {
        readers = *lock;

        if (readers != RAP_RWLOCK_WLOCK
            && rap_atomic_cmp_set(lock, readers, readers + 1))
        {
            return;
        }

        if (rap_ncpu > 1) {

            for (n = 1; n < RAP_RWLOCK_SPIN; n <<= 1) {

                for (i = 0; i < n; i++) {
                    rap_cpu_pause();
                }

                readers = *lock;

                if (readers != RAP_RWLOCK_WLOCK
                    && rap_atomic_cmp_set(lock, readers, readers + 1))
                {
                    return;
                }
            }
        }

        rap_sched_yield();
    }
}


void
rap_rwlock_unlock(rap_atomic_t *lock)
{
    rap_atomic_uint_t  readers;

    readers = *lock;

    if (readers == RAP_RWLOCK_WLOCK) {
        (void) rap_atomic_cmp_set(lock, RAP_RWLOCK_WLOCK, 0);
        return;
    }

    for ( ;; ) {

        if (rap_atomic_cmp_set(lock, readers, readers - 1)) {
            return;
        }

        readers = *lock;
    }
}


void
rap_rwlock_downgrade(rap_atomic_t *lock)
{
    if (*lock == RAP_RWLOCK_WLOCK) {
        *lock = 1;
    }
}


#else

#if (RAP_HTTP_UPSTREAM_ZONE || RAP_STREAM_UPSTREAM_ZONE)

#error rap_atomic_cmp_set() is not defined!

#endif

#endif
