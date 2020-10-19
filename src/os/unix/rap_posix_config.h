
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_POSIX_CONFIG_H_INCLUDED_
#define _RAP_POSIX_CONFIG_H_INCLUDED_


#if (RAP_HPUX)
#define _XOPEN_SOURCE
#define _XOPEN_SOURCE_EXTENDED  1
#define _HPUX_ALT_XOPEN_SOCKET_API
#endif


#if (RAP_TRU64)
#define _REENTRANT
#endif


#if (RAP_GNU_HURD)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE             /* accept4() */
#endif
#define _FILE_OFFSET_BITS       64
#endif


#ifdef __CYGWIN__
#define timezonevar             /* timezone is variable */
#define RAP_BROKEN_SCM_RIGHTS   1
#endif


#include <sys/types.h>
#include <sys/time.h>
#if (RAP_HAVE_UNISTD_H)
#include <unistd.h>
#endif
#if (RAP_HAVE_INTTYPES_H)
#include <inttypes.h>
#endif
#include <stdarg.h>
#include <stddef.h>             /* offsetof() */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <dirent.h>
#include <glob.h>
#include <time.h>
#if (RAP_HAVE_SYS_PARAM_H)
#include <sys/param.h>          /* statfs() */
#endif
#if (RAP_HAVE_SYS_MOUNT_H)
#include <sys/mount.h>          /* statfs() */
#endif
#if (RAP_HAVE_SYS_STATVFS_H)
#include <sys/statvfs.h>        /* statvfs() */
#endif

#if (RAP_HAVE_SYS_FILIO_H)
#include <sys/filio.h>          /* FIONBIO */
#endif
#include <sys/ioctl.h>          /* FIONBIO */

#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sched.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>        /* TCP_NODELAY */
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>

#if (RAP_HAVE_LIMITS_H)
#include <limits.h>             /* IOV_MAX */
#endif

#ifdef __CYGWIN__
#include <malloc.h>             /* memalign() */
#endif

#if (RAP_HAVE_CRYPT_H)
#include <crypt.h>
#endif


#ifndef IOV_MAX
#define IOV_MAX   16
#endif


#include <rap_auto_config.h>


#if (RAP_HAVE_DLOPEN)
#include <dlfcn.h>
#endif


#if (RAP_HAVE_POSIX_SEM)
#include <semaphore.h>
#endif


#if (RAP_HAVE_POLL)
#include <poll.h>
#endif


#if (RAP_HAVE_KQUEUE)
#include <sys/event.h>
#endif


#if (RAP_HAVE_DEVPOLL) && !(RAP_TEST_BUILD_DEVPOLL)
#include <sys/ioctl.h>
#include <sys/devpoll.h>
#endif


#if (RAP_HAVE_FILE_AIO)
#include <aio.h>
typedef struct aiocb  rap_aiocb_t;
#endif


#define RAP_LISTEN_BACKLOG  511

#define rap_debug_init()


extern char **environ;


#endif /* _RAP_POSIX_CONFIG_H_INCLUDED_ */
