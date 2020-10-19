
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_THREAD_H_INCLUDED_
#define _RAP_THREAD_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>

#if (RAP_THREADS)

#include <pthread.h>


typedef pthread_mutex_t  rap_thread_mutex_t;

rap_int_t rap_thread_mutex_create(rap_thread_mutex_t *mtx, rap_log_t *log);
rap_int_t rap_thread_mutex_destroy(rap_thread_mutex_t *mtx, rap_log_t *log);
rap_int_t rap_thread_mutex_lock(rap_thread_mutex_t *mtx, rap_log_t *log);
rap_int_t rap_thread_mutex_unlock(rap_thread_mutex_t *mtx, rap_log_t *log);


typedef pthread_cond_t  rap_thread_cond_t;

rap_int_t rap_thread_cond_create(rap_thread_cond_t *cond, rap_log_t *log);
rap_int_t rap_thread_cond_destroy(rap_thread_cond_t *cond, rap_log_t *log);
rap_int_t rap_thread_cond_signal(rap_thread_cond_t *cond, rap_log_t *log);
rap_int_t rap_thread_cond_wait(rap_thread_cond_t *cond, rap_thread_mutex_t *mtx,
    rap_log_t *log);


#if (RAP_LINUX)

typedef pid_t      rap_tid_t;
#define RAP_TID_T_FMT         "%P"

#elif (RAP_FREEBSD)

typedef uint32_t   rap_tid_t;
#define RAP_TID_T_FMT         "%uD"

#elif (RAP_DARWIN)

typedef uint64_t   rap_tid_t;
#define RAP_TID_T_FMT         "%uL"

#else

typedef uint64_t   rap_tid_t;
#define RAP_TID_T_FMT         "%uL"

#endif

rap_tid_t rap_thread_tid(void);

#define rap_log_tid           rap_thread_tid()

#else

#define rap_log_tid           0
#define RAP_TID_T_FMT         "%d"

#endif


#endif /* _RAP_THREAD_H_INCLUDED_ */
