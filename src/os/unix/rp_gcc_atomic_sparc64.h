
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


/*
 * "casa   [r1] 0x80, r2, r0"  and
 * "casxa  [r1] 0x80, r2, r0"  do the following:
 *
 *     if ([r1] == r2) {
 *         swap(r0, [r1]);
 *     } else {
 *         r0 = [r1];
 *     }
 *
 * so "r0 == r2" means that the operation was successful.
 *
 *
 * The "r" means the general register.
 * The "+r" means the general register used for both input and output.
 */


#if (RP_PTR_SIZE == 4)
#define RP_CASA  "casa"
#else
#define RP_CASA  "casxa"
#endif


static rp_inline rp_atomic_uint_t
rp_atomic_cmp_set(rp_atomic_t *lock, rp_atomic_uint_t old,
    rp_atomic_uint_t set)
{
    __asm__ volatile (

    RP_CASA " [%1] 0x80, %2, %0"

    : "+r" (set) : "r" (lock), "r" (old) : "memory");

    return (set == old);
}


static rp_inline rp_atomic_int_t
rp_atomic_fetch_add(rp_atomic_t *value, rp_atomic_int_t add)
{
    rp_atomic_uint_t  old, res;

    old = *value;

    for ( ;; ) {

        res = old + add;

        __asm__ volatile (

        RP_CASA " [%1] 0x80, %2, %0"

        : "+r" (res) : "r" (value), "r" (old) : "memory");

        if (res == old) {
            return res;
        }

        old = res;
    }
}


#if (RP_SMP)
#define rp_memory_barrier()                                                  \
            __asm__ volatile (                                                \
            "membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad"        \
            ::: "memory")
#else
#define rp_memory_barrier()   __asm__ volatile ("" ::: "memory")
#endif

#define rp_cpu_pause()
