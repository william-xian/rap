
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_CRC32_H_INCLUDED_
#define _RP_CRC32_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


extern uint32_t  *rp_crc32_table_short;
extern uint32_t   rp_crc32_table256[];


static rp_inline uint32_t
rp_crc32_short(u_char *p, size_t len)
{
    u_char    c;
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        c = *p++;
        crc = rp_crc32_table_short[(crc ^ (c & 0xf)) & 0xf] ^ (crc >> 4);
        crc = rp_crc32_table_short[(crc ^ (c >> 4)) & 0xf] ^ (crc >> 4);
    }

    return crc ^ 0xffffffff;
}


static rp_inline uint32_t
rp_crc32_long(u_char *p, size_t len)
{
    uint32_t  crc;

    crc = 0xffffffff;

    while (len--) {
        crc = rp_crc32_table256[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    }

    return crc ^ 0xffffffff;
}


#define rp_crc32_init(crc)                                                   \
    crc = 0xffffffff


static rp_inline void
rp_crc32_update(uint32_t *crc, u_char *p, size_t len)
{
    uint32_t  c;

    c = *crc;

    while (len--) {
        c = rp_crc32_table256[(c ^ *p++) & 0xff] ^ (c >> 8);
    }

    *crc = c;
}


#define rp_crc32_final(crc)                                                  \
    crc ^= 0xffffffff


rp_int_t rp_crc32_table_init(void);


#endif /* _RP_CRC32_H_INCLUDED_ */
