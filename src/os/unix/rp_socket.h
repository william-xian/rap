
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_SOCKET_H_INCLUDED_
#define _RP_SOCKET_H_INCLUDED_


#include <rp_config.h>


#define RP_WRITE_SHUTDOWN SHUT_WR

typedef int  rp_socket_t;

#define rp_socket          socket
#define rp_socket_n        "socket()"


#if (RP_HAVE_FIONBIO)

int rp_nonblocking(rp_socket_t s);
int rp_blocking(rp_socket_t s);

#define rp_nonblocking_n   "ioctl(FIONBIO)"
#define rp_blocking_n      "ioctl(!FIONBIO)"

#else

#define rp_nonblocking(s)  fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK)
#define rp_nonblocking_n   "fcntl(O_NONBLOCK)"

#define rp_blocking(s)     fcntl(s, F_SETFL, fcntl(s, F_GETFL) & ~O_NONBLOCK)
#define rp_blocking_n      "fcntl(!O_NONBLOCK)"

#endif

#if (RP_HAVE_FIONREAD)

#define rp_socket_nread(s, n)  ioctl(s, FIONREAD, n)
#define rp_socket_nread_n      "ioctl(FIONREAD)"

#endif

int rp_tcp_nopush(rp_socket_t s);
int rp_tcp_push(rp_socket_t s);

#if (RP_LINUX)

#define rp_tcp_nopush_n   "setsockopt(TCP_CORK)"
#define rp_tcp_push_n     "setsockopt(!TCP_CORK)"

#else

#define rp_tcp_nopush_n   "setsockopt(TCP_NOPUSH)"
#define rp_tcp_push_n     "setsockopt(!TCP_NOPUSH)"

#endif


#define rp_shutdown_socket    shutdown
#define rp_shutdown_socket_n  "shutdown()"

#define rp_close_socket    close
#define rp_close_socket_n  "close() socket"


#endif /* _RP_SOCKET_H_INCLUDED_ */
