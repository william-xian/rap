
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_USER_H_INCLUDED_
#define _RAP_USER_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef uid_t  rap_uid_t;
typedef gid_t  rap_gid_t;


rap_int_t rap_libc_crypt(rap_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);


#endif /* _RAP_USER_H_INCLUDED_ */
