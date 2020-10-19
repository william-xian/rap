
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_SOCKET_H_INCLUDED_
#define _RAP_SOCKET_H_INCLUDED_


#include <rap_config.h>


#define RAP_WRITE_SHUTDOWN SHUT_WR

typedef int  rap_socket_t;

#define rap_socket          socket
#define rap_socket_n        "socket()"


#if (RAP_HAVE_FIONBIO)

int rap_nonblocking(rap_socket_t s);
int rap_blocking(rap_socket_t s);

#define rap_nonblocking_n   "ioctl(FIONBIO)"
#define rap_blocking_n      "ioctl(!FIONBIO)"

#else

#define rap_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define rap_nonblocking_n   "fcntl(O_NONBLOCK)"

#define rap_blocking(s)     fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)
#define rap_blocking_n      "fcntl(!O_NONBLOCK)"

#endif

#if (RAP_HAVE_FIONREAD)

#define rap_socket_nread(s, n)  ioctl(s, FIONREAD, n)
#define rap_socket_nread_n      "ioctl(FIONREAD)"

#endif

int rap_tcp_nopush(rap_socket_t s);
int rap_tcp_push(rap_socket_t s);

#if (RAP_LINUX)

#define rap_tcp_nopush_n   "setsockopt(TCP_CORK)"
#define rap_tcp_push_n     "setsockopt(!TCP_CORK)"

#else

#define rap_tcp_nopush_n   "setsockopt(TCP_NOPUSH)"
#define rap_tcp_push_n     "setsockopt(!TCP_NOPUSH)"

#endif


#define rap_shutdown_socket    shutdown
#define rap_shutdown_socket_n  "shutdown()"

#define rap_close_socket    close
#define rap_close_socket_n  "close() socket"


#endif /* _RAP_SOCKET_H_INCLUDED_ */
