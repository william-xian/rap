
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


rp_int_t
rp_thread_cond_create(rp_thread_cond_t *cond, rp_log_t *log)
{
    rp_err_t  err;

    err = pthread_cond_init(cond, NULL);
    if (err == 0) {
        return RP_OK;
    }

    rp_log_error(RP_LOG_EMERG, log, err, "pthread_cond_init() failed");
    return RP_ERROR;
}


rp_int_t
rp_thread_cond_destroy(rp_thread_cond_t *cond, rp_log_t *log)
{
    rp_err_t  err;

    err = pthread_cond_destroy(cond);
    if (err == 0) {
        return RP_OK;
    }

    rp_log_error(RP_LOG_EMERG, log, err, "pthread_cond_destroy() failed");
    return RP_ERROR;
}


rp_int_t
rp_thread_cond_signal(rp_thread_cond_t *cond, rp_log_t *log)
{
    rp_err_t  err;

    err = pthread_cond_signal(cond);
    if (err == 0) {
        return RP_OK;
    }

    rp_log_error(RP_LOG_EMERG, log, err, "pthread_cond_signal() failed");
    return RP_ERROR;
}


rp_int_t
rp_thread_cond_wait(rp_thread_cond_t *cond, rp_thread_mutex_t *mtx,
    rp_log_t *log)
{
    rp_err_t  err;

    err = pthread_cond_wait(cond, mtx);

#if 0
    rp_time_update();
#endif

    if (err == 0) {
        return RP_OK;
    }

    rp_log_error(RP_LOG_ALERT, log, err, "pthread_cond_wait() failed");

    return RP_ERROR;
}
