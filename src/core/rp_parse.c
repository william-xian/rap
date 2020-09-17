
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


ssize_t
rp_parse_size(rp_str_t *line)
{
    u_char   unit;
    size_t   len;
    ssize_t  size, scale, max;

    len = line->len;

    if (len == 0) {
        return RP_ERROR;
    }

    unit = line->data[len - 1];

    switch (unit) {
    case 'K':
    case 'k':
        len--;
        max = RP_MAX_SIZE_T_VALUE / 1024;
        scale = 1024;
        break;

    case 'M':
    case 'm':
        len--;
        max = RP_MAX_SIZE_T_VALUE / (1024 * 1024);
        scale = 1024 * 1024;
        break;

    default:
        max = RP_MAX_SIZE_T_VALUE;
        scale = 1;
    }

    size = rp_atosz(line->data, len);
    if (size == RP_ERROR || size > max) {
        return RP_ERROR;
    }

    size *= scale;

    return size;
}


off_t
rp_parse_offset(rp_str_t *line)
{
    u_char  unit;
    off_t   offset, scale, max;
    size_t  len;

    len = line->len;

    if (len == 0) {
        return RP_ERROR;
    }

    unit = line->data[len - 1];

    switch (unit) {
    case 'K':
    case 'k':
        len--;
        max = RP_MAX_OFF_T_VALUE / 1024;
        scale = 1024;
        break;

    case 'M':
    case 'm':
        len--;
        max = RP_MAX_OFF_T_VALUE / (1024 * 1024);
        scale = 1024 * 1024;
        break;

    case 'G':
    case 'g':
        len--;
        max = RP_MAX_OFF_T_VALUE / (1024 * 1024 * 1024);
        scale = 1024 * 1024 * 1024;
        break;

    default:
        max = RP_MAX_OFF_T_VALUE;
        scale = 1;
    }

    offset = rp_atoof(line->data, len);
    if (offset == RP_ERROR || offset > max) {
        return RP_ERROR;
    }

    offset *= scale;

    return offset;
}


rp_int_t
rp_parse_time(rp_str_t *line, rp_uint_t is_sec)
{
    u_char      *p, *last;
    rp_int_t    value, total, scale;
    rp_int_t    max, cutoff, cutlim;
    rp_uint_t   valid;
    enum {
        st_start = 0,
        st_year,
        st_month,
        st_week,
        st_day,
        st_hour,
        st_min,
        st_sec,
        st_msec,
        st_last
    } step;

    valid = 0;
    value = 0;
    total = 0;
    cutoff = RP_MAX_INT_T_VALUE / 10;
    cutlim = RP_MAX_INT_T_VALUE % 10;
    step = is_sec ? st_start : st_month;

    p = line->data;
    last = p + line->len;

    while (p < last) {

        if (*p >= '0' && *p <= '9') {
            if (value >= cutoff && (value > cutoff || *p - '0' > cutlim)) {
                return RP_ERROR;
            }

            value = value * 10 + (*p++ - '0');
            valid = 1;
            continue;
        }

        switch (*p++) {

        case 'y':
            if (step > st_start) {
                return RP_ERROR;
            }
            step = st_year;
            max = RP_MAX_INT_T_VALUE / (60 * 60 * 24 * 365);
            scale = 60 * 60 * 24 * 365;
            break;

        case 'M':
            if (step >= st_month) {
                return RP_ERROR;
            }
            step = st_month;
            max = RP_MAX_INT_T_VALUE / (60 * 60 * 24 * 30);
            scale = 60 * 60 * 24 * 30;
            break;

        case 'w':
            if (step >= st_week) {
                return RP_ERROR;
            }
            step = st_week;
            max = RP_MAX_INT_T_VALUE / (60 * 60 * 24 * 7);
            scale = 60 * 60 * 24 * 7;
            break;

        case 'd':
            if (step >= st_day) {
                return RP_ERROR;
            }
            step = st_day;
            max = RP_MAX_INT_T_VALUE / (60 * 60 * 24);
            scale = 60 * 60 * 24;
            break;

        case 'h':
            if (step >= st_hour) {
                return RP_ERROR;
            }
            step = st_hour;
            max = RP_MAX_INT_T_VALUE / (60 * 60);
            scale = 60 * 60;
            break;

        case 'm':
            if (p < last && *p == 's') {
                if (is_sec || step >= st_msec) {
                    return RP_ERROR;
                }
                p++;
                step = st_msec;
                max = RP_MAX_INT_T_VALUE;
                scale = 1;
                break;
            }

            if (step >= st_min) {
                return RP_ERROR;
            }
            step = st_min;
            max = RP_MAX_INT_T_VALUE / 60;
            scale = 60;
            break;

        case 's':
            if (step >= st_sec) {
                return RP_ERROR;
            }
            step = st_sec;
            max = RP_MAX_INT_T_VALUE;
            scale = 1;
            break;

        case ' ':
            if (step >= st_sec) {
                return RP_ERROR;
            }
            step = st_last;
            max = RP_MAX_INT_T_VALUE;
            scale = 1;
            break;

        default:
            return RP_ERROR;
        }

        if (step != st_msec && !is_sec) {
            scale *= 1000;
            max /= 1000;
        }

        if (value > max) {
            return RP_ERROR;
        }

        value *= scale;

        if (total > RP_MAX_INT_T_VALUE - value) {
            return RP_ERROR;
        }

        total += value;

        value = 0;

        while (p < last && *p == ' ') {
            p++;
        }
    }

    if (!valid) {
        return RP_ERROR;
    }

    if (!is_sec) {
        if (value > RP_MAX_INT_T_VALUE / 1000) {
            return RP_ERROR;
        }

        value *= 1000;
    }

    if (total > RP_MAX_INT_T_VALUE - value) {
        return RP_ERROR;
    }

    return total + value;
}
