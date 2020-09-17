
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#if (RP_SMP)
#define RP_SMP_LOCK  "lock;"
#else
#define RP_SMP_LOCK
#endif


/*
 * "cmpxchgq  r, [m]":
 *
 *     if (rax == [m]) {
 *         zf = 1;
 *         [m] = r;
 *     } else {
 *         zf = 0;
 *         rax = [m];
 *     }
 *
 *
 * The "r" is any register, %rax (%r0) - %r16.
 * The "=a" and "a" are the %rax register.
 * Although we can return result in any register, we use "a" because it is
 * used in cmpxchgq anyway.  The result is actually in %al but not in $rax,
 * however as the code is inlined gcc can test %al as well as %rax.
 *
 * The "cc" means that flags were changed.
 */

static rp_inline rp_atomic_uint_t
rp_atomic_cmp_set(rp_atomic_t *lock, rp_atomic_uint_t old,
    rp_atomic_uint_t set)
{
    u_char  res;

    __asm__ volatile (

         RP_SMP_LOCK
    "    cmpxchgq  %3, %1;   "
    "    sete      %0;       "

    : "=a" (res) : "m" (*lock), "a" (old), "r" (set) : "cc", "memory");

    return res;
}


/*
 * "xaddq  r, [m]":
 *
 *     temp = [m];
 *     [m] += r;
 *     r = temp;
 *
 *
 * The "+r" is any register, %rax (%r0) - %r16.
 * The "cc" means that flags were changed.
 */

static rp_inline rp_atomic_int_t
rp_atomic_fetch_add(rp_atomic_t *value, rp_atomic_int_t add)
{
    __asm__ volatile (

         RP_SMP_LOCK
    "    xaddq  %0, %1;   "

    : "+r" (add) : "m" (*value) : "cc", "memory");

    return add;
}


#define rp_memory_barrier()    __asm__ volatile ("" ::: "memory")

#define rp_cpu_pause()         __asm__ ("pause")
