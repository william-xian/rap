
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_ERRNO_H_INCLUDED_
#define _RP_ERRNO_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef int               rp_err_t;

#define RP_EPERM         EPERM
#define RP_ENOENT        ENOENT
#define RP_ENOPATH       ENOENT
#define RP_ESRCH         ESRCH
#define RP_EINTR         EINTR
#define RP_ECHILD        ECHILD
#define RP_ENOMEM        ENOMEM
#define RP_EACCES        EACCES
#define RP_EBUSY         EBUSY
#define RP_EEXIST        EEXIST
#define RP_EEXIST_FILE   EEXIST
#define RP_EXDEV         EXDEV
#define RP_ENOTDIR       ENOTDIR
#define RP_EISDIR        EISDIR
#define RP_EINVAL        EINVAL
#define RP_ENFILE        ENFILE
#define RP_EMFILE        EMFILE
#define RP_ENOSPC        ENOSPC
#define RP_EPIPE         EPIPE
#define RP_EINPROGRESS   EINPROGRESS
#define RP_ENOPROTOOPT   ENOPROTOOPT
#define RP_EOPNOTSUPP    EOPNOTSUPP
#define RP_EADDRINUSE    EADDRINUSE
#define RP_ECONNABORTED  ECONNABORTED
#define RP_ECONNRESET    ECONNRESET
#define RP_ENOTCONN      ENOTCONN
#define RP_ETIMEDOUT     ETIMEDOUT
#define RP_ECONNREFUSED  ECONNREFUSED
#define RP_ENAMETOOLONG  ENAMETOOLONG
#define RP_ENETDOWN      ENETDOWN
#define RP_ENETUNREACH   ENETUNREACH
#define RP_EHOSTDOWN     EHOSTDOWN
#define RP_EHOSTUNREACH  EHOSTUNREACH
#define RP_ENOSYS        ENOSYS
#define RP_ECANCELED     ECANCELED
#define RP_EILSEQ        EILSEQ
#define RP_ENOMOREFILES  0
#define RP_ELOOP         ELOOP
#define RP_EBADF         EBADF

#if (RP_HAVE_OPENAT)
#define RP_EMLINK        EMLINK
#endif

#if (__hpux__)
#define RP_EAGAIN        EWOULDBLOCK
#else
#define RP_EAGAIN        EAGAIN
#endif


#define rp_errno                  errno
#define rp_socket_errno           errno
#define rp_set_errno(err)         errno = err
#define rp_set_socket_errno(err)  errno = err


u_char *rp_strerror(rp_err_t err, u_char *errstr, size_t size);
rp_int_t rp_strerror_init(void);


#endif /* _RP_ERRNO_H_INCLUDED_ */
