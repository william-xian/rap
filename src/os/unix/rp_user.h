
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_USER_H_INCLUDED_
#define _RP_USER_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef uid_t  rp_uid_t;
typedef gid_t  rp_gid_t;


rp_int_t rp_libc_crypt(rp_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);


#endif /* _RP_USER_H_INCLUDED_ */
