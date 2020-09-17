
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_SOLARIS_H_INCLUDED_
#define _RP_SOLARIS_H_INCLUDED_


rp_chain_t *rp_solaris_sendfilev_chain(rp_connection_t *c, rp_chain_t *in,
    off_t limit);


#endif /* _RP_SOLARIS_H_INCLUDED_ */
