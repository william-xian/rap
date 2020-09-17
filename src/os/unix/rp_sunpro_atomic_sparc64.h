
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#if (RP_PTR_SIZE == 4)
#define RP_CASA  rp_casa
#else
#define RP_CASA  rp_casxa
#endif


rp_atomic_uint_t
rp_casa(rp_atomic_uint_t set, rp_atomic_uint_t old, rp_atomic_t *lock);

rp_atomic_uint_t
rp_casxa(rp_atomic_uint_t set, rp_atomic_uint_t old, rp_atomic_t *lock);

/* the code in src/os/unix/rp_sunpro_sparc64.il */


static rp_inline rp_atomic_uint_t
rp_atomic_cmp_set(rp_atomic_t *lock, rp_atomic_uint_t old,
    rp_atomic_uint_t set)
{
    set = RP_CASA(set, old, lock);

    return (set == old);
}


static rp_inline rp_atomic_int_t
rp_atomic_fetch_add(rp_atomic_t *value, rp_atomic_int_t add)
{
    rp_atomic_uint_t  old, res;

    old = *value;

    for ( ;; ) {

        res = old + add;

        res = RP_CASA(res, old, value);

        if (res == old) {
            return res;
        }

        old = res;
    }
}


#define rp_memory_barrier()                                                  \
        __asm (".volatile");                                                  \
        __asm ("membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad");   \
        __asm (".nonvolatile")

#define rp_cpu_pause()
