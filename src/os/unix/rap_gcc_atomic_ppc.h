
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


/*
 * The ppc assembler treats ";" as comment, so we have to use "\n".
 * The minus in "bne-" is a hint for the branch prediction unit that
 * this branch is unlikely to be taken.
 * The "1b" means the nearest backward label "1" and the "1f" means
 * the nearest forward label "1".
 *
 * The "b" means that the base registers can be used only, i.e.
 * any register except r0.  The r0 register always has a zero value and
 * could not be used in "addi  r0, r0, 1".
 * The "=&b" means that no input registers can be used.
 *
 * "sync"    read and write barriers
 * "isync"   read barrier, is faster than "sync"
 * "eieio"   write barrier, is faster than "sync"
 * "lwsync"  write barrier, is faster than "eieio" on ppc64
 */

#if (RAP_PTR_SIZE == 8)

static rap_inline rap_atomic_uint_t
rap_atomic_cmp_set(rap_atomic_t *lock, rap_atomic_uint_t old,
    rap_atomic_uint_t set)
{
    rap_atomic_uint_t  res, temp;

    __asm__ volatile (

    "    li      %0, 0       \n" /* preset "0" to "res"                      */
    "    lwsync              \n" /* write barrier                            */
    "1:                      \n"
    "    ldarx   %1, 0, %2   \n" /* load from [lock] into "temp"             */
                                 /*   and store reservation                  */
    "    cmpd    %1, %3      \n" /* compare "temp" and "old"                 */
    "    bne-    2f          \n" /* not equal                                */
    "    stdcx.  %4, 0, %2   \n" /* store "set" into [lock] if reservation   */
                                 /*   is not cleared                         */
    "    bne-    1b          \n" /* the reservation was cleared              */
    "    isync               \n" /* read barrier                             */
    "    li      %0, 1       \n" /* set "1" to "res"                         */
    "2:                      \n"

    : "=&b" (res), "=&b" (temp)
    : "b" (lock), "b" (old), "b" (set)
    : "cc", "memory");

    return res;
}


static rap_inline rap_atomic_int_t
rap_atomic_fetch_add(rap_atomic_t *value, rap_atomic_int_t add)
{
    rap_atomic_uint_t  res, temp;

    __asm__ volatile (

    "    lwsync              \n" /* write barrier                            */
    "1:  ldarx   %0, 0, %2   \n" /* load from [value] into "res"             */
                                 /*   and store reservation                  */
    "    add     %1, %0, %3  \n" /* "res" + "add" store in "temp"            */
    "    stdcx.  %1, 0, %2   \n" /* store "temp" into [value] if reservation */
                                 /*   is not cleared                         */
    "    bne-    1b          \n" /* try again if reservation was cleared     */
    "    isync               \n" /* read barrier                             */

    : "=&b" (res), "=&b" (temp)
    : "b" (value), "b" (add)
    : "cc", "memory");

    return res;
}


#if (RAP_SMP)
#define rap_memory_barrier()                                                  \
    __asm__ volatile ("isync  \n  lwsync  \n" ::: "memory")
#else
#define rap_memory_barrier()   __asm__ volatile ("" ::: "memory")
#endif

#else

static rap_inline rap_atomic_uint_t
rap_atomic_cmp_set(rap_atomic_t *lock, rap_atomic_uint_t old,
    rap_atomic_uint_t set)
{
    rap_atomic_uint_t  res, temp;

    __asm__ volatile (

    "    li      %0, 0       \n" /* preset "0" to "res"                      */
    "    eieio               \n" /* write barrier                            */
    "1:                      \n"
    "    lwarx   %1, 0, %2   \n" /* load from [lock] into "temp"             */
                                 /*   and store reservation                  */
    "    cmpw    %1, %3      \n" /* compare "temp" and "old"                 */
    "    bne-    2f          \n" /* not equal                                */
    "    stwcx.  %4, 0, %2   \n" /* store "set" into [lock] if reservation   */
                                 /*   is not cleared                         */
    "    bne-    1b          \n" /* the reservation was cleared              */
    "    isync               \n" /* read barrier                             */
    "    li      %0, 1       \n" /* set "1" to "res"                         */
    "2:                      \n"

    : "=&b" (res), "=&b" (temp)
    : "b" (lock), "b" (old), "b" (set)
    : "cc", "memory");

    return res;
}


static rap_inline rap_atomic_int_t
rap_atomic_fetch_add(rap_atomic_t *value, rap_atomic_int_t add)
{
    rap_atomic_uint_t  res, temp;

    __asm__ volatile (

    "    eieio               \n" /* write barrier                            */
    "1:  lwarx   %0, 0, %2   \n" /* load from [value] into "res"             */
                                 /*   and store reservation                  */
    "    add     %1, %0, %3  \n" /* "res" + "add" store in "temp"            */
    "    stwcx.  %1, 0, %2   \n" /* store "temp" into [value] if reservation */
                                 /*   is not cleared                         */
    "    bne-    1b          \n" /* try again if reservation was cleared     */
    "    isync               \n" /* read barrier                             */

    : "=&b" (res), "=&b" (temp)
    : "b" (value), "b" (add)
    : "cc", "memory");

    return res;
}


#if (RAP_SMP)
#define rap_memory_barrier()                                                  \
    __asm__ volatile ("isync  \n  eieio  \n" ::: "memory")
#else
#define rap_memory_barrier()   __asm__ volatile ("" ::: "memory")
#endif

#endif


#define rap_cpu_pause()
