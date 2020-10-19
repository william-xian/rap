
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_DARWIN_H_INCLUDED_
#define _RAP_DARWIN_H_INCLUDED_


void rap_debug_init(void);
rap_chain_t *rap_darwin_sendfile_chain(rap_connection_t *c, rap_chain_t *in,
    off_t limit);

extern int       rap_darwin_kern_osreldate;
extern int       rap_darwin_hw_ncpu;
extern u_long    rap_darwin_net_inet_tcp_sendspace;

extern rap_uint_t  rap_debug_malloc;


#endif /* _RAP_DARWIN_H_INCLUDED_ */
