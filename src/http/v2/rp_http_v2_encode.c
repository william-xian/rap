
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <rp_config.h>
#include <rp_core.h>
#include <rp_http.h>


static u_char *rp_http_v2_write_int(u_char *pos, rp_uint_t prefix,
    rp_uint_t value);


u_char *
rp_http_v2_string_encode(u_char *dst, u_char *src, size_t len, u_char *tmp,
    rp_uint_t lower)
{
    size_t  hlen;

    hlen = rp_http_v2_huff_encode(src, len, tmp, lower);

    if (hlen > 0) {
        *dst = RP_HTTP_V2_ENCODE_HUFF;
        dst = rp_http_v2_write_int(dst, rp_http_v2_prefix(7), hlen);
        return rp_cpymem(dst, tmp, hlen);
    }

    *dst = RP_HTTP_V2_ENCODE_RAW;
    dst = rp_http_v2_write_int(dst, rp_http_v2_prefix(7), len);

    if (lower) {
        rp_strlow(dst, src, len);
        return dst + len;
    }

    return rp_cpymem(dst, src, len);
}


static u_char *
rp_http_v2_write_int(u_char *pos, rp_uint_t prefix, rp_uint_t value)
{
    if (value < prefix) {
        *pos++ |= value;
        return pos;
    }

    *pos++ |= prefix;
    value -= prefix;

    while (value >= 128) {
        *pos++ = value % 128 + 128;
        value /= 128;
    }

    *pos++ = (u_char) value;

    return pos;
}
