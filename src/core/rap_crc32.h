
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_CRC32_H_INCLUDED_
#define _RAP_CRC32_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


extern uint32_t  *rap_crc32_table_short;
extern uint32_t   rap_crc32_table256[];


static rap_inline uint32_t
rap_crc32_short(u_char *p, size_t len)
{
    u_char    c;
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = rap_crc32_table_short[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = rap_crc32_table_short[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}


static rap_inline uint32_t
rap_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        crc = rap_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}


#define rap_crc32_init(crc)                                                   \
    crc = 0xffffffff


static rap_inline void
rap_crc32_update(uint32_t *crc, u_char *p, size_t len)
{
    uint32_t  c;

    c = *crc;

    while (len--) {
        c = rap_crc32_table256[(c ^ *p++) & 0xff] ^ (c >> 8);
    }

    *crc = c;
}


#define rap_crc32_final(crc)                                                  \
    crc ^= 0xffffffff


rap_int_t rap_crc32_table_init(void);


#endif /* _RAP_CRC32_H_INCLUDED_ */
