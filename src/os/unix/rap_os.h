
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_OS_H_INCLUDED_
#define _RAP_OS_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


#define RAP_IO_SENDFILE    1


typedef ssize_t (*rap_recv_pt)(rap_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*rap_recv_chain_pt)(rap_connection_t *c, rap_chain_t *in,
    off_t limit);
typedef ssize_t (*rap_send_pt)(rap_connection_t *c, u_char *buf, size_t size);
typedef rap_chain_t *(*rap_send_chain_pt)(rap_connection_t *c, rap_chain_t *in,
    off_t limit);

typedef struct {
    rap_recv_pt        recv;
    rap_recv_chain_pt  recv_chain;
    rap_recv_pt        udp_recv;
    rap_send_pt        send;
    rap_send_pt        udp_send;
    rap_send_chain_pt  udp_send_chain;
    rap_send_chain_pt  send_chain;
    rap_uint_t         flags;
} rap_os_io_t;


rap_int_t rap_os_init(rap_log_t *log);
void rap_os_status(rap_log_t *log);
rap_int_t rap_os_specific_init(rap_log_t *log);
void rap_os_specific_status(rap_log_t *log);
rap_int_t rap_daemon(rap_log_t *log);
rap_int_t rap_os_signal_process(rap_cycle_t *cycle, char *sig, rap_pid_t pid);


ssize_t rap_unix_recv(rap_connection_t *c, u_char *buf, size_t size);
ssize_t rap_readv_chain(rap_connection_t *c, rap_chain_t *entry, off_t limit);
ssize_t rap_udp_unix_recv(rap_connection_t *c, u_char *buf, size_t size);
ssize_t rap_unix_send(rap_connection_t *c, u_char *buf, size_t size);
rap_chain_t *rap_writev_chain(rap_connection_t *c, rap_chain_t *in,
    off_t limit);
ssize_t rap_udp_unix_send(rap_connection_t *c, u_char *buf, size_t size);
rap_chain_t *rap_udp_unix_sendmsg_chain(rap_connection_t *c, rap_chain_t *in,
    off_t limit);


#if (IOV_MAX > 64)
#define RAP_IOVS_PREALLOCATE  64
#else
#define RAP_IOVS_PREALLOCATE  IOV_MAX
#endif


typedef struct {
    struct iovec  *iovs;
    rap_uint_t     count;
    size_t         size;
    rap_uint_t     nalloc;
} rap_iovec_t;

rap_chain_t *rap_output_chain_to_iovec(rap_iovec_t *vec, rap_chain_t *in,
    size_t limit, rap_log_t *log);


ssize_t rap_writev(rap_connection_t *c, rap_iovec_t *vec);


extern rap_os_io_t  rap_os_io;
extern rap_int_t    rap_ncpu;
extern rap_int_t    rap_max_sockets;
extern rap_uint_t   rap_inherited_nonblocking;
extern rap_uint_t   rap_tcp_nodelay_and_tcp_nopush;


#if (RAP_FREEBSD)
#include <rap_freebsd.h>


#elif (RAP_LINUX)
#include <rap_linux.h>


#elif (RAP_SOLARIS)
#include <rap_solaris.h>


#elif (RAP_DARWIN)
#include <rap_darwin.h>
#endif


#endif /* _RAP_OS_H_INCLUDED_ */
