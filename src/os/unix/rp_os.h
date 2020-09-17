
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_OS_H_INCLUDED_
#define _RP_OS_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


#define RP_IO_SENDFILE    1


typedef ssize_t (*rp_recv_pt)(rp_connection_t *c, u_char *buf, size_t size);
typedef ssize_t (*rp_recv_chain_pt)(rp_connection_t *c, rp_chain_t *in,
    off_t limit);
typedef ssize_t (*rp_send_pt)(rp_connection_t *c, u_char *buf, size_t size);
typedef rp_chain_t *(*rp_send_chain_pt)(rp_connection_t *c, rp_chain_t *in,
    off_t limit);

typedef struct {
    rp_recv_pt        recv;
    rp_recv_chain_pt  recv_chain;
    rp_recv_pt        udp_recv;
    rp_send_pt        send;
    rp_send_pt        udp_send;
    rp_send_chain_pt  udp_send_chain;
    rp_send_chain_pt  send_chain;
    rp_uint_t         flags;
} rp_os_io_t;


rp_int_t rp_os_init(rp_log_t *log);
void rp_os_status(rp_log_t *log);
rp_int_t rp_os_specific_init(rp_log_t *log);
void rp_os_specific_status(rp_log_t *log);
rp_int_t rp_daemon(rp_log_t *log);
rp_int_t rp_os_signal_process(rp_cycle_t *cycle, char *sig, rp_pid_t pid);


ssize_t rp_unix_recv(rp_connection_t *c, u_char *buf, size_t size);
ssize_t rp_readv_chain(rp_connection_t *c, rp_chain_t *entry, off_t limit);
ssize_t rp_udp_unix_recv(rp_connection_t *c, u_char *buf, size_t size);
ssize_t rp_unix_send(rp_connection_t *c, u_char *buf, size_t size);
rp_chain_t *rp_writev_chain(rp_connection_t *c, rp_chain_t *in,
    off_t limit);
ssize_t rp_udp_unix_send(rp_connection_t *c, u_char *buf, size_t size);
rp_chain_t *rp_udp_unix_sendmsg_chain(rp_connection_t *c, rp_chain_t *in,
    off_t limit);


#if (IOV_MAX > 64)
#define RP_IOVS_PREALLOCATE  64
#else
#define RP_IOVS_PREALLOCATE  IOV_MAX
#endif


typedef struct {
    struct iovec  *iovs;
    rp_uint_t     count;
    size_t         size;
    rp_uint_t     nalloc;
} rp_iovec_t;

rp_chain_t *rp_output_chain_to_iovec(rp_iovec_t *vec, rp_chain_t *in,
    size_t limit, rp_log_t *log);


ssize_t rp_writev(rp_connection_t *c, rp_iovec_t *vec);


extern rp_os_io_t  rp_os_io;
extern rp_int_t    rp_ncpu;
extern rp_int_t    rp_max_sockets;
extern rp_uint_t   rp_inherited_nonblocking;
extern rp_uint_t   rp_tcp_nodelay_and_tcp_nopush;


#if (RP_FREEBSD)
#include <rp_freebsd.h>


#elif (RP_LINUX)
#include <rp_linux.h>


#elif (RP_SOLARIS)
#include <rp_solaris.h>


#elif (RP_DARWIN)
#include <rp_darwin.h>
#endif


#endif /* _RP_OS_H_INCLUDED_ */
