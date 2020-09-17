
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_TIMES_H_INCLUDED_
#define _RP_TIMES_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct {
    time_t      sec;
    rp_uint_t  msec;
    rp_int_t   gmtoff;
} rp_time_t;


void rp_time_init(void);
void rp_time_update(void);
void rp_time_sigsafe_update(void);
u_char *rp_http_time(u_char *buf, time_t t);
u_char *rp_http_cookie_time(u_char *buf, time_t t);
void rp_gmtime(time_t t, rp_tm_t *tp);

time_t rp_next_time(time_t when);
#define rp_next_time_n      "mktime()"


extern volatile rp_time_t  *rp_cached_time;

#define rp_time()           rp_cached_time->sec
#define rp_timeofday()      (rp_time_t *) rp_cached_time

extern volatile rp_str_t    rp_cached_err_log_time;
extern volatile rp_str_t    rp_cached_http_time;
extern volatile rp_str_t    rp_cached_http_log_time;
extern volatile rp_str_t    rp_cached_http_log_iso8601;
extern volatile rp_str_t    rp_cached_syslog_time;

/*
 * milliseconds elapsed since some unspecified point in the past
 * and truncated to rp_msec_t, used in event timers
 */
extern volatile rp_msec_t  rp_current_msec;


#endif /* _RP_TIMES_H_INCLUDED_ */
