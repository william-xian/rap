
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_CONFIG_H_INCLUDED_
#define _RAP_CONFIG_H_INCLUDED_


#include <rap_auto_headers.h>


#if defined __DragonFly__ && !defined __FreeBSD__
#define __FreeBSD__        4
#define __FreeBSD_version  480101
#endif


#if (RAP_FREEBSD)
#include <rap_freebsd_config.h>


#elif (RAP_LINUX)
#include <rap_linux_config.h>


#elif (RAP_SOLARIS)
#include <rap_solaris_config.h>


#elif (RAP_DARWIN)
#include <rap_darwin_config.h>


#elif (RAP_WIN32)
#include <rap_win32_config.h>


#else /* POSIX */
#include <rap_posix_config.h>

#endif


#ifndef RAP_HAVE_SO_SNDLOWAT
#define RAP_HAVE_SO_SNDLOWAT     1
#endif


#if !(RAP_WIN32)

#define rap_signal_helper(n)     SIG##n
#define rap_signal_value(n)      rap_signal_helper(n)

#define rap_random               random

/* TODO: #ifndef */
#define RAP_SHUTDOWN_SIGNAL      QUIT
#define RAP_TERMINATE_SIGNAL     TERM
#define RAP_NOACCEPT_SIGNAL      WINCH
#define RAP_RECONFIGURE_SIGNAL   HUP

#if (RAP_LINUXTHREADS)
#define RAP_REOPEN_SIGNAL        INFO
#define RAP_CHANGEBIN_SIGNAL     XCPU
#else
#define RAP_REOPEN_SIGNAL        USR1
#define RAP_CHANGEBIN_SIGNAL     USR2
#endif

#define rap_cdecl
#define rap_libc_cdecl

#endif

typedef intptr_t        rap_int_t;
typedef uintptr_t       rap_uint_t;
typedef intptr_t        rap_flag_t;


#define RAP_INT32_LEN   (sizeof("-2147483648") - 1)
#define RAP_INT64_LEN   (sizeof("-9223372036854775808") - 1)

#if (RAP_PTR_SIZE == 4)
#define RAP_INT_T_LEN   RAP_INT32_LEN
#define RAP_MAX_INT_T_VALUE  2147483647

#else
#define RAP_INT_T_LEN   RAP_INT64_LEN
#define RAP_MAX_INT_T_VALUE  9223372036854775807
#endif


#ifndef RAP_ALIGNMENT
#define RAP_ALIGNMENT   sizeof(unsigned long)    /* platform word */
#endif

#define rap_align(d, a)     (((d) + (a - 1)) & ~(a - 1))
#define rap_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))


#define rap_abort       abort


/* TODO: platform specific: array[RAP_INVALID_ARRAY_INDEX] must cause SIGSEGV */
#define RAP_INVALID_ARRAY_INDEX 0x80000000


/* TODO: auto_conf: rap_inline   inline __inline __inline__ */
#ifndef rap_inline
#define rap_inline      inline
#endif

#ifndef INADDR_NONE  /* Solaris */
#define INADDR_NONE  ((unsigned int) -1)
#endif

#ifdef MAXHOSTNAMELEN
#define RAP_MAXHOSTNAMELEN  MAXHOSTNAMELEN
#else
#define RAP_MAXHOSTNAMELEN  256
#endif


#define RAP_MAX_UINT32_VALUE  (uint32_t) 0xffffffff
#define RAP_MAX_INT32_VALUE   (uint32_t) 0x7fffffff


#if (RAP_COMPAT)

#define RAP_COMPAT_BEGIN(slots)  uint64_t spare[slots];
#define RAP_COMPAT_END

#else

#define RAP_COMPAT_BEGIN(slots)
#define RAP_COMPAT_END

#endif


#endif /* _RAP_CONFIG_H_INCLUDED_ */
