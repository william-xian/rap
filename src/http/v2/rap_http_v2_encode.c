
/*
 * Copyright (C) Rap, Inc.
 * Copyright (C) Valentin V. Bartenev
 */


#include <rap_config.h>
#include <rap_core.h>
#include <rap_http.h>


static u_char *rap_http_v2_write_int(u_char *pos, rap_uint_t prefix,
    rap_uint_t value);


u_char *
rap_http_v2_string_encode(u_char *dst, u_char *src, size_t len, u_char *tmp,
    rap_uint_t lower)
{
    size_t  hlen;

    hlen = rap_http_v2_huff_encode(src, len, tmp, lower);

    if (hlen > 0) {
        *dst = RAP_HTTP_V2_ENCODE_HUFF;
        dst = rap_http_v2_write_int(dst, rap_http_v2_prefix(7), hlen);
        return rap_cpymem(dst, tmp, hlen);
    }

    *dst = RAP_HTTP_V2_ENCODE_RAW;
    dst = rap_http_v2_write_int(dst, rap_http_v2_prefix(7), len);

    if (lower) {
        rap_strlow(dst, src, len);
        return dst + len;
    }

    return rap_cpymem(dst, src, len);
}


static u_char *
rap_http_v2_write_int(u_char *pos, rap_uint_t prefix, rap_uint_t value)
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
