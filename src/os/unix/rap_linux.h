
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_LINUX_H_INCLUDED_
#define _RAP_LINUX_H_INCLUDED_


rap_chain_t *rap_linux_sendfile_chain(rap_connection_t *c, rap_chain_t *in,
    off_t limit);


#endif /* _RAP_LINUX_H_INCLUDED_ */
