
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_MD5_H_INCLUDED_
#define _RP_MD5_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d;
    u_char    buffer[64];
} rp_md5_t;


void rp_md5_init(rp_md5_t *ctx);
void rp_md5_update(rp_md5_t *ctx, const void *data, size_t size);
void rp_md5_final(u_char result[16], rp_md5_t *ctx);


#endif /* _RP_MD5_H_INCLUDED_ */
