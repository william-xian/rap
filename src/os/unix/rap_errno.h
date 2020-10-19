
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_ERRNO_H_INCLUDED_
#define _RAP_ERRNO_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef int               rap_err_t;

#define RAP_EPERM         EPERM
#define RAP_ENOENT        ENOENT
#define RAP_ENOPATH       ENOENT
#define RAP_ESRCH         ESRCH
#define RAP_EINTR         EINTR
#define RAP_ECHILD        ECHILD
#define RAP_ENOMEM        ENOMEM
#define RAP_EACCES        EACCES
#define RAP_EBUSY         EBUSY
#define RAP_EEXIST        EEXIST
#define RAP_EEXIST_FILE   EEXIST
#define RAP_EXDEV         EXDEV
#define RAP_ENOTDIR       ENOTDIR
#define RAP_EISDIR        EISDIR
#define RAP_EINVAL        EINVAL
#define RAP_ENFILE        ENFILE
#define RAP_EMFILE        EMFILE
#define RAP_ENOSPC        ENOSPC
#define RAP_EPIPE         EPIPE
#define RAP_EINPROGRESS   EINPROGRESS
#define RAP_ENOPROTOOPT   ENOPROTOOPT
#define RAP_EOPNOTSUPP    EOPNOTSUPP
#define RAP_EADDRINUSE    EADDRINUSE
#define RAP_ECONNABORTED  ECONNABORTED
#define RAP_ECONNRESET    ECONNRESET
#define RAP_ENOTCONN      ENOTCONN
#define RAP_ETIMEDOUT     ETIMEDOUT
#define RAP_ECONNREFUSED  ECONNREFUSED
#define RAP_ENAMETOOLONG  ENAMETOOLONG
#define RAP_ENETDOWN      ENETDOWN
#define RAP_ENETUNREACH   ENETUNREACH
#define RAP_EHOSTDOWN     EHOSTDOWN
#define RAP_EHOSTUNREACH  EHOSTUNREACH
#define RAP_ENOSYS        ENOSYS
#define RAP_ECANCELED     ECANCELED
#define RAP_EILSEQ        EILSEQ
#define RAP_ENOMOREFILES  0
#define RAP_ELOOP         ELOOP
#define RAP_EBADF         EBADF

#if (RAP_HAVE_OPENAT)
#define RAP_EMLINK        EMLINK
#endif

#if (__hpux__)
#define RAP_EAGAIN        EWOULDBLOCK
#else
#define RAP_EAGAIN        EAGAIN
#endif


#define rap_errno                  errno
#define rap_socket_errno           errno
#define rap_set_errno(err)         errno = err
#define rap_set_socket_errno(err)  errno = err


u_char *rap_strerror(rap_err_t err, u_char *errstr, size_t size);
rap_int_t rap_strerror_init(void);


#endif /* _RAP_ERRNO_H_INCLUDED_ */
