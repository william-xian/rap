
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_TIME_H_INCLUDED_
#define _RP_TIME_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef rp_rbtree_key_t      rp_msec_t;
typedef rp_rbtree_key_int_t  rp_msec_int_t;

typedef struct tm             rp_tm_t;

#define rp_tm_sec            tm_sec
#define rp_tm_min            tm_min
#define rp_tm_hour           tm_hour
#define rp_tm_mday           tm_mday
#define rp_tm_mon            tm_mon
#define rp_tm_year           tm_year
#define rp_tm_wday           tm_wday
#define rp_tm_isdst          tm_isdst

#define rp_tm_sec_t          int
#define rp_tm_min_t          int
#define rp_tm_hour_t         int
#define rp_tm_mday_t         int
#define rp_tm_mon_t          int
#define rp_tm_year_t         int
#define rp_tm_wday_t         int


#if (RP_HAVE_GMTOFF)
#define rp_tm_gmtoff         tm_gmtoff
#define rp_tm_zone           tm_zone
#endif


#if (RP_SOLARIS)

#define rp_timezone(isdst) (- (isdst ? altzone : timezone) / 60)

#else

#define rp_timezone(isdst) (- (isdst ? timezone + 3600 : timezone) / 60)

#endif


void rp_timezone_update(void);
void rp_localtime(time_t s, rp_tm_t *tm);
void rp_libc_localtime(time_t s, struct tm *tm);
void rp_libc_gmtime(time_t s, struct tm *tm);

#define rp_gettimeofday(tp)  (void) gettimeofday(tp, NULL);
#define rp_msleep(ms)        (void) usleep(ms * 1000)
#define rp_sleep(s)          (void) sleep(s)


#endif /* _RP_TIME_H_INCLUDED_ */
