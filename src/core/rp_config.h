
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_CONFIG_H_INCLUDED_
#define _RP_CONFIG_H_INCLUDED_


#include <rp_auto_headers.h>


#if defined __DragonFly__ && !defined __FreeBSD__
#define __FreeBSD__        4
#define __FreeBSD_version  480101
#endif


#if (RP_FREEBSD)
#include <rp_freebsd_config.h>


#elif (RP_LINUX)
#include <rp_linux_config.h>


#elif (RP_SOLARIS)
#include <rp_solaris_config.h>


#elif (RP_DARWIN)
#include <rp_darwin_config.h>


#elif (RP_WIN32)
#include <rp_win32_config.h>


#else /* POSIX */
#include <rp_posix_config.h>

#endif


#ifndef RP_HAVE_SO_SNDLOWAT
#define RP_HAVE_SO_SNDLOWAT     1
#endif


#if !(RP_WIN32)

#define rp_signal_helper(n)     SIG##n
#define rp_signal_value(n)      rp_signal_helper(n)

#define rp_random               random

/* TODO: #ifndef */
#define RP_SHUTDOWN_SIGNAL      QUIT
#define RP_TERMINATE_SIGNAL     TERM
#define RP_NOACCEPT_SIGNAL      WINCH
#define RP_RECONFIGURE_SIGNAL   HUP

#if (RP_LINUXTHREADS)
#define RP_REOPEN_SIGNAL        INFO
#define RP_CHANGEBIN_SIGNAL     XCPU
#else
#define RP_REOPEN_SIGNAL        USR1
#define RP_CHANGEBIN_SIGNAL     USR2
#endif

#define rp_cdecl
#define rp_libc_cdecl

#endif

typedef intptr_t        rp_int_t;
typedef uintptr_t       rp_uint_t;
typedef intptr_t        rp_flag_t;


#define RP_INT32_LEN   (sizeof("-2147483648") - 1)
#define RP_INT64_LEN   (sizeof("-9223372036854775808") - 1)

#if (RP_PTR_SIZE == 4)
#define RP_INT_T_LEN   RP_INT32_LEN
#define RP_MAX_INT_T_VALUE  2147483647

#else
#define RP_INT_T_LEN   RP_INT64_LEN
#define RP_MAX_INT_T_VALUE  9223372036854775807
#endif


#ifndef RP_ALIGNMENT
#define RP_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

#define rp_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define rp_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


#define rp_abort       abort


/* TODO: platform specific: array[RP_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define RP_INVALID_ARRAY_INDEX 0x80000000


/* TODO: auto_conf: rp_inline   inline __inline __inline__ */
#ifndef rp_inline
#define rp_inline      inline
#endif

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

#ifdef MAXHOSTNAMELEN
#define RP_MAXHOSTNAMELEN  MAXHOSTNAMELEN
#else
#define RP_MAXHOSTNAMELEN  256
#endif


#define RP_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#define RP_MAX_INT32_VALUE   (uint32_t) 0x7fffffff


#if (RP_COMPAT)

#define RP_COMPAT_BEGIN(slots)  uint64_t spare[slots];
#define RP_COMPAT_END

#else

#define RP_COMPAT_BEGIN(slots)
#define RP_COMPAT_END

#endif


#endif /* _RP_CONFIG_H_INCLUDED_ */
