
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_CRYPT_H_INCLUDED_
#define _RP_CRYPT_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


rp_int_t rp_crypt(rp_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);


#endif /* _RP_CRYPT_H_INCLUDED_ */
