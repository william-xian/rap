
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


ssize_t
rap_parse_size(rap_str_t *line)
{
    u_char   unit;
    size_t   len;
    ssize_t  size, scale, max;

    len = line->len;

    if (len == 0) {
        return RAP_ERROR;
    }

    unit = line->data[len - 1];

    switch (unit) {
    case 'K':
    case 'k':
        len--;
        max = RAP_MAX_SIZE_T_VALUE / 1024;
        scale = 1024;
        break;

    case 'M':
    case 'm':
        len--;
        max = RAP_MAX_SIZE_T_VALUE / (1024 * 1024);
        scale = 1024 * 1024;
        break;

    default:
        max = RAP_MAX_SIZE_T_VALUE;
        scale = 1;
    }

    size = rap_atosz(line->data, len);
    if (size == RAP_ERROR || size > max) {
        return RAP_ERROR;
    }

    size *= scale;

    return size;
}


off_t
rap_parse_offset(rap_str_t *line)
{
    u_char  unit;
    off_t   offset, scale, max;
    size_t  len;

    len = line->len;

    if (len == 0) {
        return RAP_ERROR;
    }

    unit = line->data[len - 1];

    switch (unit) {
    case 'K':
    case 'k':
        len--;
        max = RAP_MAX_OFF_T_VALUE / 1024;
        scale = 1024;
        break;

    case 'M':
    case 'm':
        len--;
        max = RAP_MAX_OFF_T_VALUE / (1024 * 1024);
        scale = 1024 * 1024;
        break;

    case 'G':
    case 'g':
        len--;
        max = RAP_MAX_OFF_T_VALUE / (1024 * 1024 * 1024);
        scale = 1024 * 1024 * 1024;
        break;

    default:
        max = RAP_MAX_OFF_T_VALUE;
        scale = 1;
    }

    offset = rap_atoof(line->data, len);
    if (offset == RAP_ERROR || offset > max) {
        return RAP_ERROR;
    }

    offset *= scale;

    return offset;
}


rap_int_t
rap_parse_time(rap_str_t *line, rap_uint_t is_sec)
{
    u_char      *p, *last;
    rap_int_t    value, total, scale;
    rap_int_t    max, cutoff, cutlim;
    rap_uint_t   valid;
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
    cutoff = RAP_MAX_INT_T_VALUE / 10;
    cutlim = RAP_MAX_INT_T_VALUE % 10;
    step = is_sec ? st_start : st_month;

    p = line->data;
    last = p + line->len;

    while (p < last) {

        if (*p >= '0' && *p <= '9') {
            if (value >= cutoff && (value > cutoff || *p - '0' > cutlim)) {
                return RAP_ERROR;
            }

            value = value * 10 + (*p++ - '0');
            valid = 1;
            continue;
        }

        switch (*p++) {

        case 'y':
            if (step > st_start) {
                return RAP_ERROR;
            }
            step = st_year;
            max = RAP_MAX_INT_T_VALUE / (60 * 60 * 24 * 365);
            scale = 60 * 60 * 24 * 365;
            break;

        case 'M':
            if (step >= st_month) {
                return RAP_ERROR;
            }
            step = st_month;
            max = RAP_MAX_INT_T_VALUE / (60 * 60 * 24 * 30);
            scale = 60 * 60 * 24 * 30;
            break;

        case 'w':
            if (step >= st_week) {
                return RAP_ERROR;
            }
            step = st_week;
            max = RAP_MAX_INT_T_VALUE / (60 * 60 * 24 * 7);
            scale = 60 * 60 * 24 * 7;
            break;

        case 'd':
            if (step >= st_day) {
                return RAP_ERROR;
            }
            step = st_day;
            max = RAP_MAX_INT_T_VALUE / (60 * 60 * 24);
            scale = 60 * 60 * 24;
            break;

        case 'h':
            if (step >= st_hour) {
                return RAP_ERROR;
            }
            step = st_hour;
            max = RAP_MAX_INT_T_VALUE / (60 * 60);
            scale = 60 * 60;
            break;

        case 'm':
            if (p < last && *p == 's') {
                if (is_sec || step >= st_msec) {
                    return RAP_ERROR;
                }
                p++;
                step = st_msec;
                max = RAP_MAX_INT_T_VALUE;
                scale = 1;
                break;
            }

            if (step >= st_min) {
                return RAP_ERROR;
            }
            step = st_min;
            max = RAP_MAX_INT_T_VALUE / 60;
            scale = 60;
            break;

        case 's':
            if (step >= st_sec) {
                return RAP_ERROR;
            }
            step = st_sec;
            max = RAP_MAX_INT_T_VALUE;
            scale = 1;
            break;

        case ' ':
            if (step >= st_sec) {
                return RAP_ERROR;
            }
            step = st_last;
            max = RAP_MAX_INT_T_VALUE;
            scale = 1;
            break;

        default:
            return RAP_ERROR;
        }

        if (step != st_msec && !is_sec) {
            scale *= 1000;
            max /= 1000;
        }

        if (value > max) {
            return RAP_ERROR;
        }

        value *= scale;

        if (total > RAP_MAX_INT_T_VALUE - value) {
            return RAP_ERROR;
        }

        total += value;

        value = 0;

        while (p < last && *p == ' ') {
            p++;
        }
    }

    if (!valid) {
        return RAP_ERROR;
    }

    if (!is_sec) {
        if (value > RAP_MAX_INT_T_VALUE / 1000) {
            return RAP_ERROR;
        }

        value *= 1000;
    }

    if (total > RAP_MAX_INT_T_VALUE - value) {
        return RAP_ERROR;
    }

    return total + value;
}
