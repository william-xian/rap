
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_SHA1_H_INCLUDED_
#define _RP_SHA1_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d, e, f;
    u_char    buffer[64];
} rp_sha1_t;


void rp_sha1_init(rp_sha1_t *ctx);
void rp_sha1_update(rp_sha1_t *ctx, const void *data, size_t size);
void rp_sha1_final(u_char result[20], rp_sha1_t *ctx);


#endif /* _RP_SHA1_H_INCLUDED_ */
