
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_CRYPT_H_INCLUDED_
#define _RAP_CRYPT_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


rap_int_t rap_crypt(rap_pool_t *pool, u_char *key, u_char *salt,
    u_char **encrypted);


#endif /* _RAP_CRYPT_H_INCLUDED_ */
