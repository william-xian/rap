
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


rap_int_t
rap_thread_cond_create(rap_thread_cond_t *cond, rap_log_t *log)
{
    rap_err_t  err;

    err = pthread_cond_init(cond, NULL);
    if (err == 0) {
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_EMERG, log, err, "pthread_cond_init() failed");
    return RAP_ERROR;
}


rap_int_t
rap_thread_cond_destroy(rap_thread_cond_t *cond, rap_log_t *log)
{
    rap_err_t  err;

    err = pthread_cond_destroy(cond);
    if (err == 0) {
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_EMERG, log, err, "pthread_cond_destroy() failed");
    return RAP_ERROR;
}


rap_int_t
rap_thread_cond_signal(rap_thread_cond_t *cond, rap_log_t *log)
{
    rap_err_t  err;

    err = pthread_cond_signal(cond);
    if (err == 0) {
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_EMERG, log, err, "pthread_cond_signal() failed");
    return RAP_ERROR;
}


rap_int_t
rap_thread_cond_wait(rap_thread_cond_t *cond, rap_thread_mutex_t *mtx,
    rap_log_t *log)
{
    rap_err_t  err;

    err = pthread_cond_wait(cond, mtx);

#if 0
    rap_time_update();
#endif

    if (err == 0) {
        return RAP_OK;
    }

    rap_log_error(RAP_LOG_ALERT, log, err, "pthread_cond_wait() failed");

    return RAP_ERROR;
}
