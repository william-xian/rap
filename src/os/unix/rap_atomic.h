
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_ATOMIC_H_INCLUDED_
#define _RAP_ATOMIC_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#if (RAP_HAVE_LIBATOMIC)

#define AO_REQUIRE_CAS
#include <atomic_ops.h>

#define RAP_HAVE_ATOMIC_OPS  1

typedef long                        rap_atomic_int_t;
typedef AO_t                        rap_atomic_uint_t;
typedef volatile rap_atomic_uint_t  rap_atomic_t;

#if (RAP_PTR_SIZE == 8)
#define RAP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
#else
#define RAP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
#endif

#define rap_atomic_cmp_set(lock, old, new)                                    \
    AO_compare_and_swap(lock, old, new)
#define rap_atomic_fetch_add(value, add)                                      \
    AO_fetch_and_add(value, add)
#define rap_memory_barrier()        AO_nop()
#define rap_cpu_pause()


#elif (RAP_DARWIN_ATOMIC)

/*
 * use Darwin 8 atomic(3) and barrier(3) operations
 * optimized at run-time for UP and SMP
 */

#include <libkern/OSAtomic.h>

/* "bool" conflicts with perl's CORE/handy.h */
#if 0
#undef bool
#endif


#define RAP_HAVE_ATOMIC_OPS  1

#if (RAP_PTR_SIZE == 8)

typedef int64_t                     rap_atomic_int_t;
typedef uint64_t                    rap_atomic_uint_t;
#define RAP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)

#define rap_atomic_cmp_set(lock, old, new)                                    \
    OSAtomicCompareAndSwap64Barrier(old, new, (int64_t *) lock)

#define rap_atomic_fetch_add(value, add)                                      \
    (OSAtomicAdd64(add, (int64_t *) value) - add)

#else

typedef int32_t                     rap_atomic_int_t;
typedef uint32_t                    rap_atomic_uint_t;
#define RAP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)

#define rap_atomic_cmp_set(lock, old, new)                                    \
    OSAtomicCompareAndSwap32Barrier(old, new, (int32_t *) lock)

#define rap_atomic_fetch_add(value, add)                                      \
    (OSAtomicAdd32(add, (int32_t *) value) - add)

#endif

#define rap_memory_barrier()        OSMemoryBarrier()

#define rap_cpu_pause()

typedef volatile rap_atomic_uint_t  rap_atomic_t;


#elif (RAP_HAVE_GCC_ATOMIC)

/* GCC 4.1 builtin atomic operations */

#define RAP_HAVE_ATOMIC_OPS  1

typedef long                        rap_atomic_int_t;
typedef unsigned long               rap_atomic_uint_t;

#if (RAP_PTR_SIZE == 8)
#define RAP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
#else
#define RAP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
#endif

typedef volatile rap_atomic_uint_t  rap_atomic_t;


#define rap_atomic_cmp_set(lock, old, set)                                    \
    __sync_bool_compare_and_swap(lock, old, set)

#define rap_atomic_fetch_add(value, add)                                      \
    __sync_fetch_and_add(value, add)

#define rap_memory_barrier()        __sync_synchronize()

#if ( __i386__ || __i386 || __amd64__ || __amd64 )
#define rap_cpu_pause()             __asm__ ("pause")
#else
#define rap_cpu_pause()
#endif


#elif ( __i386__ || __i386 )

typedef int32_t                     rap_atomic_int_t;
typedef uint32_t                    rap_atomic_uint_t;
typedef volatile rap_atomic_uint_t  rap_atomic_t;
#define RAP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)


#if ( __SUNPRO_C )

#define RAP_HAVE_ATOMIC_OPS  1

rap_atomic_uint_t
rap_atomic_cmp_set(rap_atomic_t *lock, rap_atomic_uint_t old,
    rap_atomic_uint_t set);

rap_atomic_int_t
rap_atomic_fetch_add(rap_atomic_t *value, rap_atomic_int_t add);

/*
 * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
 * so rap_cpu_pause is declared in src/os/unix/rap_sunpro_x86.il
 */

void
rap_cpu_pause(void);

/* the code in src/os/unix/rap_sunpro_x86.il */

#define rap_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define RAP_HAVE_ATOMIC_OPS  1

#include "rap_gcc_atomic_x86.h"

#endif


#elif ( __amd64__ || __amd64 )

typedef int64_t                     rap_atomic_int_t;
typedef uint64_t                    rap_atomic_uint_t;
typedef volatile rap_atomic_uint_t  rap_atomic_t;
#define RAP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)


#if ( __SUNPRO_C )

#define RAP_HAVE_ATOMIC_OPS  1

rap_atomic_uint_t
rap_atomic_cmp_set(rap_atomic_t *lock, rap_atomic_uint_t old,
    rap_atomic_uint_t set);

rap_atomic_int_t
rap_atomic_fetch_add(rap_atomic_t *value, rap_atomic_int_t add);

/*
 * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
 * so rap_cpu_pause is declared in src/os/unix/rap_sunpro_amd64.il
 */

void
rap_cpu_pause(void);

/* the code in src/os/unix/rap_sunpro_amd64.il */

#define rap_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define RAP_HAVE_ATOMIC_OPS  1

#include "rap_gcc_atomic_amd64.h"

#endif


#elif ( __sparc__ || __sparc || __sparcv9 )

#if (RAP_PTR_SIZE == 8)

typedef int64_t                     rap_atomic_int_t;
typedef uint64_t                    rap_atomic_uint_t;
#define RAP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)

#else

typedef int32_t                     rap_atomic_int_t;
typedef uint32_t                    rap_atomic_uint_t;
#define RAP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)

#endif

typedef volatile rap_atomic_uint_t  rap_atomic_t;


#if ( __SUNPRO_C )

#define RAP_HAVE_ATOMIC_OPS  1

#include "rap_sunpro_atomic_sparc64.h"


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define RAP_HAVE_ATOMIC_OPS  1

#include "rap_gcc_atomic_sparc64.h"

#endif


#elif ( __powerpc__ || __POWERPC__ )

#define RAP_HAVE_ATOMIC_OPS  1

#if (RAP_PTR_SIZE == 8)

typedef int64_t                     rap_atomic_int_t;
typedef uint64_t                    rap_atomic_uint_t;
#define RAP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)

#else

typedef int32_t                     rap_atomic_int_t;
typedef uint32_t                    rap_atomic_uint_t;
#define RAP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)

#endif

typedef volatile rap_atomic_uint_t  rap_atomic_t;


#include "rap_gcc_atomic_ppc.h"

#endif


#if !(RAP_HAVE_ATOMIC_OPS)

#define RAP_HAVE_ATOMIC_OPS  0

typedef int32_t                     rap_atomic_int_t;
typedef uint32_t                    rap_atomic_uint_t;
typedef volatile rap_atomic_uint_t  rap_atomic_t;
#define RAP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)


static rap_inline rap_atomic_uint_t
rap_atomic_cmp_set(rap_atomic_t *lock, rap_atomic_uint_t old,
    rap_atomic_uint_t set)
{
    if (*lock == old) {
        *lock = set;
        return 1;
    }

    return 0;
}


static rap_inline rap_atomic_int_t
rap_atomic_fetch_add(rap_atomic_t *value, rap_atomic_int_t add)
{
    rap_atomic_int_t  old;

    old = *value;
    *value += add;

    return old;
}

#define rap_memory_barrier()
#define rap_cpu_pause()

#endif


void rap_spinlock(rap_atomic_t *lock, rap_atomic_int_t value, rap_uint_t spin);

#define rap_trylock(lock)  (*(lock) == 0 && rap_atomic_cmp_set(lock, 0, 1))
#define rap_unlock(lock)    *(lock) = 0


#endif /* _RAP_ATOMIC_H_INCLUDED_ */
