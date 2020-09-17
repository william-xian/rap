
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_LINUX_H_INCLUDED_
#define _RP_LINUX_H_INCLUDED_


rp_chain_t *rp_linux_sendfile_chain(rp_connection_t *c, rp_chain_t *in,
    off_t limit);


#endif /* _RP_LINUX_H_INCLUDED_ */
