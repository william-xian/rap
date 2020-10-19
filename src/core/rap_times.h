
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_TIMES_H_INCLUDED_
#define _RAP_TIMES_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct {
    time_t      sec;
    rap_uint_t  msec;
    rap_int_t   gmtoff;
} rap_time_t;


void rap_time_init(void);
void rap_time_update(void);
void rap_time_sigsafe_update(void);
u_char *rap_http_time(u_char *buf, time_t t);
u_char *rap_http_cookie_time(u_char *buf, time_t t);
void rap_gmtime(time_t t, rap_tm_t *tp);

time_t rap_next_time(time_t when);
#define rap_next_time_n      "mktime()"


extern volatile rap_time_t  *rap_cached_time;

#define rap_time()           rap_cached_time->sec
#define rap_timeofday()      (rap_time_t *) rap_cached_time

extern volatile rap_str_t    rap_cached_err_log_time;
extern volatile rap_str_t    rap_cached_http_time;
extern volatile rap_str_t    rap_cached_http_log_time;
extern volatile rap_str_t    rap_cached_http_log_iso8601;
extern volatile rap_str_t    rap_cached_syslog_time;

/*
 * milliseconds elapsed since some unspecified point in the past
 * and truncated to rap_msec_t, used in event timers
 */
extern volatile rap_msec_t  rap_current_msec;


#endif /* _RAP_TIMES_H_INCLUDED_ */
