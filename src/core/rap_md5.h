
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_MD5_H_INCLUDED_
#define _RAP_MD5_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d;
    u_char    buffer[64];
} rap_md5_t;


void rap_md5_init(rap_md5_t *ctx);
void rap_md5_update(rap_md5_t *ctx, const void *data, size_t size);
void rap_md5_final(u_char result[16], rap_md5_t *ctx);


#endif /* _RAP_MD5_H_INCLUDED_ */
