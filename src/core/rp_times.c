
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


static rp_msec_t rp_monotonic_time(time_t sec, rp_uint_t msec);


/*
 * The time may be updated by signal handler or by several threads.
 * The time update operations are rare and require to hold the rp_time_lock.
 * The time read operations are frequent, so they are lock-free and get time
 * values and strings from the current slot.  Thus thread may get the corrupted
 * values only if it is preempted while copying and then it is not scheduled
 * to run more than RP_TIME_SLOTS seconds.
 */

#define RP_TIME_SLOTS   64

static rp_uint_t        slot;
static rp_atomic_t      rp_time_lock;

volatile rp_msec_t      rp_current_msec;
volatile rp_time_t     *rp_cached_time;
volatile rp_str_t       rp_cached_err_log_time;
volatile rp_str_t       rp_cached_http_time;
volatile rp_str_t       rp_cached_http_log_time;
volatile rp_str_t       rp_cached_http_log_iso8601;
volatile rp_str_t       rp_cached_syslog_time;

#if !(RP_WIN32)

/*
 * localtime() and localtime_r() are not Async-Signal-Safe functions, therefore,
 * they must not be called by a signal handler, so we use the cached
 * GMT offset value. Fortunately the value is changed only two times a year.
 */

static rp_int_t         cached_gmtoff;
#endif

static rp_time_t        cached_time[RP_TIME_SLOTS];
static u_char            cached_err_log_time[RP_TIME_SLOTS]
                                    [sizeof("1970/09/28 12:00:00")];
static u_char            cached_http_time[RP_TIME_SLOTS]
                                    [sizeof("Mon, 28 Sep 1970 06:00:00 GMT")];
static u_char            cached_http_log_time[RP_TIME_SLOTS]
                                    [sizeof("28/Sep/1970:12:00:00 +0600")];
static u_char            cached_http_log_iso8601[RP_TIME_SLOTS]
                                    [sizeof("1970-09-28T12:00:00+06:00")];
static u_char            cached_syslog_time[RP_TIME_SLOTS]
                                    [sizeof("Sep 28 12:00:00")];


static char  *week[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
static char  *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

void
rp_time_init(void)
{
    rp_cached_err_log_time.len = sizeof("1970/09/28 12:00:00") - 1;
    rp_cached_http_time.len = sizeof("Mon, 28 Sep 1970 06:00:00 GMT") - 1;
    rp_cached_http_log_time.len = sizeof("28/Sep/1970:12:00:00 +0600") - 1;
    rp_cached_http_log_iso8601.len = sizeof("1970-09-28T12:00:00+06:00") - 1;
    rp_cached_syslog_time.len = sizeof("Sep 28 12:00:00") - 1;

    rp_cached_time = &cached_time[0];

    rp_time_update();
}


void
rp_time_update(void)
{
    u_char          *p0, *p1, *p2, *p3, *p4;
    rp_tm_t         tm, gmt;
    time_t           sec;
    rp_uint_t       msec;
    rp_time_t      *tp;
    struct timeval   tv;

    if (!rp_trylock(&rp_time_lock)) {
        return;
    }

    rp_gettimeofday(&tv);

    sec = tv.tv_sec;
    msec = tv.tv_usec / 1000;

    rp_current_msec = rp_monotonic_time(sec, msec);

    tp = &cached_time[slot];

    if (tp->sec == sec) {
        tp->msec = msec;
        rp_unlock(&rp_time_lock);
        return;
    }

    if (slot == RP_TIME_SLOTS - 1) {
        slot = 0;
    } else {
        slot++;
    }

    tp = &cached_time[slot];

    tp->sec = sec;
    tp->msec = msec;

    rp_gmtime(sec, &gmt);


    p0 = &cached_http_time[slot][0];

    (void) rp_sprintf(p0, "%s, %02d %s %4d %02d:%02d:%02d GMT",
                       week[gmt.rp_tm_wday], gmt.rp_tm_mday,
                       months[gmt.rp_tm_mon - 1], gmt.rp_tm_year,
                       gmt.rp_tm_hour, gmt.rp_tm_min, gmt.rp_tm_sec);

#if (RP_HAVE_GETTIMEZONE)

    tp->gmtoff = rp_gettimezone();
    rp_gmtime(sec + tp->gmtoff * 60, &tm);

#elif (RP_HAVE_GMTOFF)

    rp_localtime(sec, &tm);
    cached_gmtoff = (rp_int_t) (tm.rp_tm_gmtoff / 60);
    tp->gmtoff = cached_gmtoff;

#else

    rp_localtime(sec, &tm);
    cached_gmtoff = rp_timezone(tm.rp_tm_isdst);
    tp->gmtoff = cached_gmtoff;

#endif


    p1 = &cached_err_log_time[slot][0];

    (void) rp_sprintf(p1, "%4d/%02d/%02d %02d:%02d:%02d",
                       tm.rp_tm_year, tm.rp_tm_mon,
                       tm.rp_tm_mday, tm.rp_tm_hour,
                       tm.rp_tm_min, tm.rp_tm_sec);


    p2 = &cached_http_log_time[slot][0];

    (void) rp_sprintf(p2, "%02d/%s/%d:%02d:%02d:%02d %c%02i%02i",
                       tm.rp_tm_mday, months[tm.rp_tm_mon - 1],
                       tm.rp_tm_year, tm.rp_tm_hour,
                       tm.rp_tm_min, tm.rp_tm_sec,
                       tp->gmtoff < 0 ? '-' : '+',
                       rp_abs(tp->gmtoff / 60), rp_abs(tp->gmtoff % 60));

    p3 = &cached_http_log_iso8601[slot][0];

    (void) rp_sprintf(p3, "%4d-%02d-%02dT%02d:%02d:%02d%c%02i:%02i",
                       tm.rp_tm_year, tm.rp_tm_mon,
                       tm.rp_tm_mday, tm.rp_tm_hour,
                       tm.rp_tm_min, tm.rp_tm_sec,
                       tp->gmtoff < 0 ? '-' : '+',
                       rp_abs(tp->gmtoff / 60), rp_abs(tp->gmtoff % 60));

    p4 = &cached_syslog_time[slot][0];

    (void) rp_sprintf(p4, "%s %2d %02d:%02d:%02d",
                       months[tm.rp_tm_mon - 1], tm.rp_tm_mday,
                       tm.rp_tm_hour, tm.rp_tm_min, tm.rp_tm_sec);

    rp_memory_barrier();

    rp_cached_time = tp;
    rp_cached_http_time.data = p0;
    rp_cached_err_log_time.data = p1;
    rp_cached_http_log_time.data = p2;
    rp_cached_http_log_iso8601.data = p3;
    rp_cached_syslog_time.data = p4;

    rp_unlock(&rp_time_lock);
}


static rp_msec_t
rp_monotonic_time(time_t sec, rp_uint_t msec)
{
#if (RP_HAVE_CLOCK_MONOTONIC)
    struct timespec  ts;

#if defined(CLOCK_MONOTONIC_FAST)
    clock_gettime(CLOCK_MONOTONIC_FAST, &ts);

#elif defined(CLOCK_MONOTONIC_COARSE)
    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);

#else
    clock_gettime(CLOCK_MONOTONIC, &ts);
#endif

    sec = ts.tv_sec;
    msec = ts.tv_nsec / 1000000;

#endif

    return (rp_msec_t) sec * 1000 + msec;
}


#if !(RP_WIN32)

void
rp_time_sigsafe_update(void)
{
    u_char          *p, *p2;
    rp_tm_t         tm;
    time_t           sec;
    rp_time_t      *tp;
    struct timeval   tv;

    if (!rp_trylock(&rp_time_lock)) {
        return;
    }

    rp_gettimeofday(&tv);

    sec = tv.tv_sec;

    tp = &cached_time[slot];

    if (tp->sec == sec) {
        rp_unlock(&rp_time_lock);
        return;
    }

    if (slot == RP_TIME_SLOTS - 1) {
        slot = 0;
    } else {
        slot++;
    }

    tp = &cached_time[slot];

    tp->sec = 0;

    rp_gmtime(sec + cached_gmtoff * 60, &tm);

    p = &cached_err_log_time[slot][0];

    (void) rp_sprintf(p, "%4d/%02d/%02d %02d:%02d:%02d",
                       tm.rp_tm_year, tm.rp_tm_mon,
                       tm.rp_tm_mday, tm.rp_tm_hour,
                       tm.rp_tm_min, tm.rp_tm_sec);

    p2 = &cached_syslog_time[slot][0];

    (void) rp_sprintf(p2, "%s %2d %02d:%02d:%02d",
                       months[tm.rp_tm_mon - 1], tm.rp_tm_mday,
                       tm.rp_tm_hour, tm.rp_tm_min, tm.rp_tm_sec);

    rp_memory_barrier();

    rp_cached_err_log_time.data = p;
    rp_cached_syslog_time.data = p2;

    rp_unlock(&rp_time_lock);
}

#endif


u_char *
rp_http_time(u_char *buf, time_t t)
{
    rp_tm_t  tm;

    rp_gmtime(t, &tm);

    return rp_sprintf(buf, "%s, %02d %s %4d %02d:%02d:%02d GMT",
                       week[tm.rp_tm_wday],
                       tm.rp_tm_mday,
                       months[tm.rp_tm_mon - 1],
                       tm.rp_tm_year,
                       tm.rp_tm_hour,
                       tm.rp_tm_min,
                       tm.rp_tm_sec);
}


u_char *
rp_http_cookie_time(u_char *buf, time_t t)
{
    rp_tm_t  tm;

    rp_gmtime(t, &tm);

    /*
     * Netscape 3.x does not understand 4-digit years at all and
     * 2-digit years more than "37"
     */

    return rp_sprintf(buf,
                       (tm.rp_tm_year > 2037) ?
                                         "%s, %02d-%s-%d %02d:%02d:%02d GMT":
                                         "%s, %02d-%s-%02d %02d:%02d:%02d GMT",
                       week[tm.rp_tm_wday],
                       tm.rp_tm_mday,
                       months[tm.rp_tm_mon - 1],
                       (tm.rp_tm_year > 2037) ? tm.rp_tm_year:
                                                 tm.rp_tm_year % 100,
                       tm.rp_tm_hour,
                       tm.rp_tm_min,
                       tm.rp_tm_sec);
}


void
rp_gmtime(time_t t, rp_tm_t *tp)
{
    rp_int_t   yday;
    rp_uint_t  sec, min, hour, mday, mon, year, wday, days, leap;

    /* the calculation is valid for positive time_t only */

    if (t < 0) {
        t = 0;
    }

    days = t / 86400;
    sec = t % 86400;

    /*
     * no more than 4 year digits supported,
     * truncate to December 31, 9999, 23:59:59
     */

    if (days > 2932896) {
        days = 2932896;
        sec = 86399;
    }

    /* January 1, 1970 was Thursday */

    wday = (4 + days) % 7;

    hour = sec / 3600;
    sec %= 3600;
    min = sec / 60;
    sec %= 60;

    /*
     * the algorithm based on Gauss' formula,
     * see src/core/rp_parse_time.c
     */

    /* days since March 1, 1 BC */
    days = days - (31 + 28) + 719527;

    /*
     * The "days" should be adjusted to 1 only, however, some March 1st's go
     * to previous year, so we adjust them to 2.  This causes also shift of the
     * last February days to next year, but we catch the case when "yday"
     * becomes negative.
     */

    year = (days + 2) * 400 / (365 * 400 + 100 - 4 + 1);

    yday = days - (365 * year + year / 4 - year / 100 + year / 400);

    if (yday < 0) {
        leap = (year % 4 == 0) && (year % 100 || (year % 400 == 0));
        yday = 365 + leap + yday;
        year--;
    }

    /*
     * The empirical formula that maps "yday" to month.
     * There are at least 10 variants, some of them are:
     *     mon = (yday + 31) * 15 / 459
     *     mon = (yday + 31) * 17 / 520
     *     mon = (yday + 31) * 20 / 612
     */

    mon = (yday + 31) * 10 / 306;

    /* the Gauss' formula that evaluates days before the month */

    mday = yday - (367 * mon / 12 - 30) + 1;

    if (yday >= 306) {

        year++;
        mon -= 10;

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday -= 306;
         */

    } else {

        mon += 2;

        /*
         * there is no "yday" in Win32 SYSTEMTIME
         *
         * yday += 31 + 28 + leap;
         */
    }

    tp->rp_tm_sec = (rp_tm_sec_t) sec;
    tp->rp_tm_min = (rp_tm_min_t) min;
    tp->rp_tm_hour = (rp_tm_hour_t) hour;
    tp->rp_tm_mday = (rp_tm_mday_t) mday;
    tp->rp_tm_mon = (rp_tm_mon_t) mon;
    tp->rp_tm_year = (rp_tm_year_t) year;
    tp->rp_tm_wday = (rp_tm_wday_t) wday;
}


time_t
rp_next_time(time_t when)
{
    time_t     now, next;
    struct tm  tm;

    now = rp_time();

    rp_libc_localtime(now, &tm);

    tm.tm_hour = (int) (when / 3600);
    when %= 3600;
    tm.tm_min = (int) (when / 60);
    tm.tm_sec = (int) (when % 60);

    next = mktime(&tm);

    if (next == -1) {
        return -1;
    }

    if (next - now > 0) {
        return next;
    }

    tm.tm_mday++;

    /* mktime() should normalize a date (Jan 32, etc) */

    next = mktime(&tm);

    if (next != -1) {
        return next;
    }

    return -1;
}
