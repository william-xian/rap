
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


#if (RAP_PTR_SIZE == 4)
#define RAP_CASA  "casa"
#else
#define RAP_CASA  "casxa"
#endif


static rap_inline rap_atomic_uint_t
rap_atomic_cmp_set(rap_atomic_t *lock, rap_atomic_uint_t old,
    rap_atomic_uint_t set)
{
    __asm__ volatile (

    RAP_CASA " [%1] 0x80, %2, %0"

    : "+r" (set) : "r" (lock), "r" (old) : "memory");

    return (set == old);
}


static rap_inline rap_atomic_int_t
rap_atomic_fetch_add(rap_atomic_t *value, rap_atomic_int_t add)
{
    rap_atomic_uint_t  old, res;

    old = *value;

    for ( ;; ) {

        res = old + add;

        __asm__ volatile (

        RAP_CASA " [%1] 0x80, %2, %0"

        : "+r" (res) : "r" (value), "r" (old) : "memory");

        if (res == old) {
            return res;
        }

        old = res;
    }
}


#if (RAP_SMP)
#define rap_memory_barrier()                                                  \
            __asm__ volatile (                                                \
            "membar #LoadLoad | #LoadStore | #StoreStore | #StoreLoad"        \
            ::: "memory")
#else
#define rap_memory_barrier()   __asm__ volatile ("" ::: "memory")
#endif

#define rap_cpu_pause()
