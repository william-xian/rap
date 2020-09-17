
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_FREEBSD_H_INCLUDED_
#define _RP_FREEBSD_H_INCLUDED_


void rp_debug_init(void);
rp_chain_t *rp_freebsd_sendfile_chain(rp_connection_t *c, rp_chain_t *in,
    off_t limit);

extern int         rp_freebsd_kern_osreldate;
extern int         rp_freebsd_hw_ncpu;
extern u_long      rp_freebsd_net_inet_tcp_sendspace;

extern rp_uint_t  rp_freebsd_sendfile_nbytes_bug;
extern rp_uint_t  rp_freebsd_use_tcp_nopush;
extern rp_uint_t  rp_debug_malloc;


#endif /* _RP_FREEBSD_H_INCLUDED_ */
