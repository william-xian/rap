
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#if (RAP_PTR_SIZE == 4)
#define RAP_CASA  rap_casa
#else
#define RAP_CASA  rap_casxa
#endif


rap_atomic_uint_t
rap_casa(rap_atomic_uint_t set, rap_atomic_uint_t old, rap_atomic_t *lock);

rap_atomic_uint_t
rap_casxa(rap_atomic_uint_t set, rap_atomic_uint_t old, rap_atomic_t *lock);

/* the code in src/os/unix/rap_sunpro_sparc64.il */


static rap_inline rap_atomic_uint_t
rap_atomic_cmp_set(rap_atomic_t *lock, rap_atomic_uint_t old,
    rap_atomic_uint_t set)
{
    set = RAP_CASA(set, old, lock);

    return (set == old);
}


static rap_inline rap_atomic_int_t
rap_atomic_fetch_add(rap_atomic_t *value, rap_atomic_int_t add)
{
    rap_atomic_uint_t  old, res;

    old = *value;

    for ( ;; ) {

        res = old + add;

        res = RAP_CASA(res, old, value);

        if (res == old) {
            return res;
        }

        old = res;
    }
}


#define rap_memory_barrier()                                                  \
        __asm (".volatile");                                                  \
        __asm ("membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad");   \
        __asm (".nonvolatile")

#define rap_cpu_pause()
