
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_TIME_H_INCLUDED_
#define _RAP_TIME_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef rap_rbtree_key_t      rap_msec_t;
typedef rap_rbtree_key_int_t  rap_msec_int_t;

typedef struct tm             rap_tm_t;

#define rap_tm_sec            tm_sec
#define rap_tm_min            tm_min
#define rap_tm_hour           tm_hour
#define rap_tm_mday           tm_mday
#define rap_tm_mon            tm_mon
#define rap_tm_year           tm_year
#define rap_tm_wday           tm_wday
#define rap_tm_isdst          tm_isdst

#define rap_tm_sec_t          int
#define rap_tm_min_t          int
#define rap_tm_hour_t         int
#define rap_tm_mday_t         int
#define rap_tm_mon_t          int
#define rap_tm_year_t         int
#define rap_tm_wday_t         int


#if (RAP_HAVE_GMTOFF)
#define rap_tm_gmtoff         tm_gmtoff
#define rap_tm_zone           tm_zone
#endif


#if (RAP_SOLARIS)

#define rap_timezone(isdst) (- (isdst ? altzone : timezone) / 60)

#else

#define rap_timezone(isdst) (- (isdst ? timezone + 3600 : timezone) / 60)

#endif


void rap_timezone_update(void);
void rap_localtime(time_t s, rap_tm_t *tm);
void rap_libc_localtime(time_t s, struct tm *tm);
void rap_libc_gmtime(time_t s, struct tm *tm);

#define rap_gettimeofday(tp)  (void) gettimeofday(tp, NULL);
#define rap_msleep(ms)        (void) usleep(ms * 1000)
#define rap_sleep(s)          (void) sleep(s)


#endif /* _RAP_TIME_H_INCLUDED_ */
