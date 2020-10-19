
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_CRC_H_INCLUDED_
#define _RAP_CRC_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


/* 32-bit crc16 */

static rap_inline uint32_t
rap_crc(u_char *data, size_t len)
{
    uint32_t  sum;

    for (sum = 0; len; len--) {

        /*
         * gcc 2.95.2 x86 and icc 7.1.006 compile
         * that operator into the single "rol" opcode,
         * msvc 6.0sp2 compiles it into four opcodes.
         */
        sum = sum >> 1 | sum << 31;

        sum += *data++;
    }

    return sum;
}


#endif /* _RAP_CRC_H_INCLUDED_ */
