
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_SHA1_H_INCLUDED_
#define _RAP_SHA1_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d, e, f;
    u_char    buffer[64];
} rap_sha1_t;


void rap_sha1_init(rap_sha1_t *ctx);
void rap_sha1_update(rap_sha1_t *ctx, const void *data, size_t size);
void rap_sha1_final(u_char result[20], rap_sha1_t *ctx);


#endif /* _RAP_SHA1_H_INCLUDED_ */
