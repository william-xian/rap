
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_THREAD_H_INCLUDED_
#define _RP_THREAD_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>

#if (RP_THREADS)

#include <pthread.h>


typedef pthread_mutex_t  rp_thread_mutex_t;

rp_int_t rp_thread_mutex_create(rp_thread_mutex_t *mtx, rp_log_t *log);
rp_int_t rp_thread_mutex_destroy(rp_thread_mutex_t *mtx, rp_log_t *log);
rp_int_t rp_thread_mutex_lock(rp_thread_mutex_t *mtx, rp_log_t *log);
rp_int_t rp_thread_mutex_unlock(rp_thread_mutex_t *mtx, rp_log_t *log);


typedef pthread_cond_t  rp_thread_cond_t;

rp_int_t rp_thread_cond_create(rp_thread_cond_t *cond, rp_log_t *log);
rp_int_t rp_thread_cond_destroy(rp_thread_cond_t *cond, rp_log_t *log);
rp_int_t rp_thread_cond_signal(rp_thread_cond_t *cond, rp_log_t *log);
rp_int_t rp_thread_cond_wait(rp_thread_cond_t *cond, rp_thread_mutex_t *mtx,
    rp_log_t *log);


#if (RP_LINUX)

typedef pid_t      rp_tid_t;
#define RP_TID_T_FMT         "%P"

#elif (RP_FREEBSD)

typedef uint32_t   rp_tid_t;
#define RP_TID_T_FMT         "%uD"

#elif (RP_DARWIN)

typedef uint64_t   rp_tid_t;
#define RP_TID_T_FMT         "%uL"

#else

typedef uint64_t   rp_tid_t;
#define RP_TID_T_FMT         "%uL"

#endif

rp_tid_t rp_thread_tid(void);

#define rp_log_tid           rp_thread_tid()

#else

#define rp_log_tid           0
#define RP_TID_T_FMT         "%d"

#endif


#endif /* _RP_THREAD_H_INCLUDED_ */
