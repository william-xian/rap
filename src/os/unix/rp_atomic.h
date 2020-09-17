
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_ATOMIC_H_INCLUDED_
#define _RP_ATOMIC_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#if (RP_HAVE_LIBATOMIC)

#define AO_REQUIRE_CAS
#include <atomic_ops.h>

#define RP_HAVE_ATOMIC_OPS  1

typedef long                        rp_atomic_int_t;
typedef AO_t                        rp_atomic_uint_t;
typedef volatile rp_atomic_uint_t  rp_atomic_t;

#if (RP_PTR_SIZE == 8)
#define RP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
#else
#define RP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
#endif

#define rp_atomic_cmp_set(lock, old, new)                                    \
    AO_compare_and_swap(lock, old, new)
#define rp_atomic_fetch_add(value, add)                                      \
    AO_fetch_and_add(value, add)
#define rp_memory_barrier()        AO_nop()
#define rp_cpu_pause()


#elif (RP_DARWIN_ATOMIC)

/*
 * use Darwin 8 atomic(3) and barrier(3) operations
 * optimized at run-time for UP and SMP
 */

#include <libkern/OSAtomic.h>

/* "bool" conflicts with perl's CORE/handy.h */
#if 0
#undef bool
#endif


#define RP_HAVE_ATOMIC_OPS  1

#if (RP_PTR_SIZE == 8)

typedef int64_t                     rp_atomic_int_t;
typedef uint64_t                    rp_atomic_uint_t;
#define RP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)

#define rp_atomic_cmp_set(lock, old, new)                                    \
    OSAtomicCompareAndSwap64Barrier(old, new, (int64_t *) lock)

#define rp_atomic_fetch_add(value, add)                                      \
    (OSAtomicAdd64(add, (int64_t *) value) - add)

#else

typedef int32_t                     rp_atomic_int_t;
typedef uint32_t                    rp_atomic_uint_t;
#define RP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)

#define rp_atomic_cmp_set(lock, old, new)                                    \
    OSAtomicCompareAndSwap32Barrier(old, new, (int32_t *) lock)

#define rp_atomic_fetch_add(value, add)                                      \
    (OSAtomicAdd32(add, (int32_t *) value) - add)

#endif

#define rp_memory_barrier()        OSMemoryBarrier()

#define rp_cpu_pause()

typedef volatile rp_atomic_uint_t  rp_atomic_t;


#elif (RP_HAVE_GCC_ATOMIC)

/* GCC 4.1 builtin atomic operations */

#define RP_HAVE_ATOMIC_OPS  1

typedef long                        rp_atomic_int_t;
typedef unsigned long               rp_atomic_uint_t;

#if (RP_PTR_SIZE == 8)
#define RP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)
#else
#define RP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)
#endif

typedef volatile rp_atomic_uint_t  rp_atomic_t;


#define rp_atomic_cmp_set(lock, old, set)                                    \
    __sync_bool_compare_and_swap(lock, old, set)

#define rp_atomic_fetch_add(value, add)                                      \
    __sync_fetch_and_add(value, add)

#define rp_memory_barrier()        __sync_synchronize()

#if ( __i386__ || __i386 || __amd64__ || __amd64 )
#define rp_cpu_pause()             __asm__ ("pause")
#else
#define rp_cpu_pause()
#endif


#elif ( __i386__ || __i386 )

typedef int32_t                     rp_atomic_int_t;
typedef uint32_t                    rp_atomic_uint_t;
typedef volatile rp_atomic_uint_t  rp_atomic_t;
#define RP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)


#if ( __SUNPRO_C )

#define RP_HAVE_ATOMIC_OPS  1

rp_atomic_uint_t
rp_atomic_cmp_set(rp_atomic_t *lock, rp_atomic_uint_t old,
    rp_atomic_uint_t set);

rp_atomic_int_t
rp_atomic_fetch_add(rp_atomic_t *value, rp_atomic_int_t add);

/*
 * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
 * so rp_cpu_pause is declared in src/os/unix/rp_sunpro_x86.il
 */

void
rp_cpu_pause(void);

/* the code in src/os/unix/rp_sunpro_x86.il */

#define rp_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define RP_HAVE_ATOMIC_OPS  1

#include "rp_gcc_atomic_x86.h"

#endif


#elif ( __amd64__ || __amd64 )

typedef int64_t                     rp_atomic_int_t;
typedef uint64_t                    rp_atomic_uint_t;
typedef volatile rp_atomic_uint_t  rp_atomic_t;
#define RP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)


#if ( __SUNPRO_C )

#define RP_HAVE_ATOMIC_OPS  1

rp_atomic_uint_t
rp_atomic_cmp_set(rp_atomic_t *lock, rp_atomic_uint_t old,
    rp_atomic_uint_t set);

rp_atomic_int_t
rp_atomic_fetch_add(rp_atomic_t *value, rp_atomic_int_t add);

/*
 * Sun Studio 12 exits with segmentation fault on '__asm ("pause")',
 * so rp_cpu_pause is declared in src/os/unix/rp_sunpro_amd64.il
 */

void
rp_cpu_pause(void);

/* the code in src/os/unix/rp_sunpro_amd64.il */

#define rp_memory_barrier()        __asm (".volatile"); __asm (".nonvolatile")


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define RP_HAVE_ATOMIC_OPS  1

#include "rp_gcc_atomic_amd64.h"

#endif


#elif ( __sparc__ || __sparc || __sparcv9 )

#if (RP_PTR_SIZE == 8)

typedef int64_t                     rp_atomic_int_t;
typedef uint64_t                    rp_atomic_uint_t;
#define RP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)

#else

typedef int32_t                     rp_atomic_int_t;
typedef uint32_t                    rp_atomic_uint_t;
#define RP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)

#endif

typedef volatile rp_atomic_uint_t  rp_atomic_t;


#if ( __SUNPRO_C )

#define RP_HAVE_ATOMIC_OPS  1

#include "rp_sunpro_atomic_sparc64.h"


#else /* ( __GNUC__ || __INTEL_COMPILER ) */

#define RP_HAVE_ATOMIC_OPS  1

#include "rp_gcc_atomic_sparc64.h"

#endif


#elif ( __powerpc__ || __POWERPC__ )

#define RP_HAVE_ATOMIC_OPS  1

#if (RP_PTR_SIZE == 8)

typedef int64_t                     rp_atomic_int_t;
typedef uint64_t                    rp_atomic_uint_t;
#define RP_ATOMIC_T_LEN            (sizeof("-9223372036854775808") - 1)

#else

typedef int32_t                     rp_atomic_int_t;
typedef uint32_t                    rp_atomic_uint_t;
#define RP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)

#endif

typedef volatile rp_atomic_uint_t  rp_atomic_t;


#include "rp_gcc_atomic_ppc.h"

#endif


#if !(RP_HAVE_ATOMIC_OPS)

#define RP_HAVE_ATOMIC_OPS  0

typedef int32_t                     rp_atomic_int_t;
typedef uint32_t                    rp_atomic_uint_t;
typedef volatile rp_atomic_uint_t  rp_atomic_t;
#define RP_ATOMIC_T_LEN            (sizeof("-2147483648") - 1)


static rp_inline rp_atomic_uint_t
rp_atomic_cmp_set(rp_atomic_t *lock, rp_atomic_uint_t old,
    rp_atomic_uint_t set)
{
    if (*lock == old) {
        *lock = set;
        return 1;
    }

    return 0;
}


static rp_inline rp_atomic_int_t
rp_atomic_fetch_add(rp_atomic_t *value, rp_atomic_int_t add)
{
    rp_atomic_int_t  old;

    old = *value;
    *value += add;

    return old;
}

#define rp_memory_barrier()
#define rp_cpu_pause()

#endif


void rp_spinlock(rp_atomic_t *lock, rp_atomic_int_t value, rp_uint_t spin);

#define rp_trylock(lock)  (*(lock) == 0 && rp_atomic_cmp_set(lock, 0, 1))
#define rp_unlock(lock)    *(lock) = 0


#endif /* _RP_ATOMIC_H_INCLUDED_ */
