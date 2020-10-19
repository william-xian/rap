
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#if (RAP_HAVE_ATOMIC_OPS)


static void rap_shmtx_wakeup(rap_shmtx_t *mtx);


rap_int_t
rap_shmtx_create(rap_shmtx_t *mtx, rap_shmtx_sh_t *addr, u_char *name)
{
    mtx->lock = &addr->lock;

    if (mtx->spin == (rap_uint_t) -1) {
        return RAP_OK;
    }

    mtx->spin = 2048;

#if (RAP_HAVE_POSIX_SEM)

    mtx->wait = &addr->wait;

    if (sem_init(&mtx->sem, 1, 0) == -1) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_errno,
                      "sem_init() failed");
    } else {
        mtx->semaphore = 1;
    }

#endif

    return RAP_OK;
}


void
rap_shmtx_destroy(rap_shmtx_t *mtx)
{
#if (RAP_HAVE_POSIX_SEM)

    if (mtx->semaphore) {
        if (sem_destroy(&mtx->sem) == -1) {
            rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_errno,
                          "sem_destroy() failed");
        }
    }

#endif
}


rap_uint_t
rap_shmtx_trylock(rap_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && rap_atomic_cmp_set(mtx->lock, 0, rap_pid));
}


void
rap_shmtx_lock(rap_shmtx_t *mtx)
{
    rap_uint_t         i, n;

    rap_log_debug0(RAP_LOG_DEBUG_CORE, rap_cycle->log, 0, "shmtx lock");

    for ( ;; ) {

        if (*mtx->lock == 0 && rap_atomic_cmp_set(mtx->lock, 0, rap_pid)) {
            return;
        }

        if (rap_ncpu > 1) {

            for (n = 1; n < mtx->spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    rap_cpu_pause();
                }

                if (*mtx->lock == 0
                    && rap_atomic_cmp_set(mtx->lock, 0, rap_pid))
                {
                    return;
                }
            }
        }

#if (RAP_HAVE_POSIX_SEM)

        if (mtx->semaphore) {
            (void) rap_atomic_fetch_add(mtx->wait, 1);

            if (*mtx->lock == 0 && rap_atomic_cmp_set(mtx->lock, 0, rap_pid)) {
                (void) rap_atomic_fetch_add(mtx->wait, -1);
                return;
            }

            rap_log_debug1(RAP_LOG_DEBUG_CORE, rap_cycle->log, 0,
                           "shmtx wait %uA", *mtx->wait);

            while (sem_wait(&mtx->sem) == -1) {
                rap_err_t  err;

                err = rap_errno;

                if (err != RAP_EINTR) {
                    rap_log_error(RAP_LOG_ALERT, rap_cycle->log, err,
                                  "sem_wait() failed while waiting on shmtx");
                    break;
                }
            }

            rap_log_debug0(RAP_LOG_DEBUG_CORE, rap_cycle->log, 0,
                           "shmtx awoke");

            continue;
        }

#endif

        rap_sched_yield();
    }
}


void
rap_shmtx_unlock(rap_shmtx_t *mtx)
{
    if (mtx->spin != (rap_uint_t) -1) {
        rap_log_debug0(RAP_LOG_DEBUG_CORE, rap_cycle->log, 0, "shmtx unlock");
    }

    if (rap_atomic_cmp_set(mtx->lock, rap_pid, 0)) {
        rap_shmtx_wakeup(mtx);
    }
}


rap_uint_t
rap_shmtx_force_unlock(rap_shmtx_t *mtx, rap_pid_t pid)
{
    rap_log_debug0(RAP_LOG_DEBUG_CORE, rap_cycle->log, 0,
                   "shmtx forced unlock");

    if (rap_atomic_cmp_set(mtx->lock, pid, 0)) {
        rap_shmtx_wakeup(mtx);
        return 1;
    }

    return 0;
}


static void
rap_shmtx_wakeup(rap_shmtx_t *mtx)
{
#if (RAP_HAVE_POSIX_SEM)
    rap_atomic_uint_t  wait;

    if (!mtx->semaphore) {
        return;
    }

    for ( ;; ) {

        wait = *mtx->wait;

        if ((rap_atomic_int_t) wait <= 0) {
            return;
        }

        if (rap_atomic_cmp_set(mtx->wait, wait, wait - 1)) {
            break;
        }
    }

    rap_log_debug1(RAP_LOG_DEBUG_CORE, rap_cycle->log, 0,
                   "shmtx wake %uA", wait);

    if (sem_post(&mtx->sem) == -1) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_errno,
                      "sem_post() failed while wake shmtx");
    }

#endif
}


#else


rap_int_t
rap_shmtx_create(rap_shmtx_t *mtx, rap_shmtx_sh_t *addr, u_char *name)
{
    if (mtx->name) {

        if (rap_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            return RAP_OK;
        }

        rap_shmtx_destroy(mtx);
    }

    mtx->fd = rap_open_file(name, RAP_FILE_RDWR, RAP_FILE_CREATE_OR_OPEN,
                            RAP_FILE_DEFAULT_ACCESS);

    if (mtx->fd == RAP_INVALID_FILE) {
        rap_log_error(RAP_LOG_EMERG, rap_cycle->log, rap_errno,
                      rap_open_file_n " \"%s\" failed", name);
        return RAP_ERROR;
    }

    if (rap_delete_file(name) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_errno,
                      rap_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return RAP_OK;
}


void
rap_shmtx_destroy(rap_shmtx_t *mtx)
{
    if (rap_close_file(mtx->fd) == RAP_FILE_ERROR) {
        rap_log_error(RAP_LOG_ALERT, rap_cycle->log, rap_errno,
                      rap_close_file_n " \"%s\" failed", mtx->name);
    }
}


rap_uint_t
rap_shmtx_trylock(rap_shmtx_t *mtx)
{
    rap_err_t  err;

    err = rap_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == RAP_EAGAIN) {
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == RAP_EACCES) {
        return 0;
    }

#endif

    rap_log_abort(err, rap_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


void
rap_shmtx_lock(rap_shmtx_t *mtx)
{
    rap_err_t  err;

    err = rap_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    rap_log_abort(err, rap_lock_fd_n " %s failed", mtx->name);
}


void
rap_shmtx_unlock(rap_shmtx_t *mtx)
{
    rap_err_t  err;

    err = rap_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    rap_log_abort(err, rap_unlock_fd_n " %s failed", mtx->name);
}


rap_uint_t
rap_shmtx_force_unlock(rap_shmtx_t *mtx, rap_pid_t pid)
{
    return 0;
}

#endif
