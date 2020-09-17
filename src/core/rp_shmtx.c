
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#if (RP_HAVE_ATOMIC_OPS)


static void rp_shmtx_wakeup(rp_shmtx_t *mtx);


rp_int_t
rp_shmtx_create(rp_shmtx_t *mtx, rp_shmtx_sh_t *addr, u_char *name)
{
    mtx->lock = &addr->lock;

    if (mtx->spin == (rp_uint_t) -1) {
        return RP_OK;
    }

    mtx->spin = 2048;

#if (RP_HAVE_POSIX_SEM)

    mtx->wait = &addr->wait;

    if (sem_init(&mtx->sem, 1, 0) == -1) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_errno,
                      "sem_init() failed");
    } else {
        mtx->semaphore = 1;
    }

#endif

    return RP_OK;
}


void
rp_shmtx_destroy(rp_shmtx_t *mtx)
{
#if (RP_HAVE_POSIX_SEM)

    if (mtx->semaphore) {
        if (sem_destroy(&mtx->sem) == -1) {
            rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_errno,
                          "sem_destroy() failed");
        }
    }

#endif
}


rp_uint_t
rp_shmtx_trylock(rp_shmtx_t *mtx)
{
    return (*mtx->lock == 0 && rp_atomic_cmp_set(mtx->lock, 0, rp_pid));
}


void
rp_shmtx_lock(rp_shmtx_t *mtx)
{
    rp_uint_t         i, n;

    rp_log_debug0(RP_LOG_DEBUG_CORE, rp_cycle->log, 0, "shmtx lock");

    for ( ;; ) {

        if (*mtx->lock == 0 && rp_atomic_cmp_set(mtx->lock, 0, rp_pid)) {
            return;
        }

        if (rp_ncpu > 1) {

            for (n = 1; n < mtx->spin; n <<= 1) {

                for (i = 0; i < n; i++) {
                    rp_cpu_pause();
                }

                if (*mtx->lock == 0
                    && rp_atomic_cmp_set(mtx->lock, 0, rp_pid))
                {
                    return;
                }
            }
        }

#if (RP_HAVE_POSIX_SEM)

        if (mtx->semaphore) {
            (void) rp_atomic_fetch_add(mtx->wait, 1);

            if (*mtx->lock == 0 && rp_atomic_cmp_set(mtx->lock, 0, rp_pid)) {
                (void) rp_atomic_fetch_add(mtx->wait, -1);
                return;
            }

            rp_log_debug1(RP_LOG_DEBUG_CORE, rp_cycle->log, 0,
                           "shmtx wait %uA", *mtx->wait);

            while (sem_wait(&mtx->sem) == -1) {
                rp_err_t  err;

                err = rp_errno;

                if (err != RP_EINTR) {
                    rp_log_error(RP_LOG_ALERT, rp_cycle->log, err,
                                  "sem_wait() failed while waiting on shmtx");
                    break;
                }
            }

            rp_log_debug0(RP_LOG_DEBUG_CORE, rp_cycle->log, 0,
                           "shmtx awoke");

            continue;
        }

#endif

        rp_sched_yield();
    }
}


void
rp_shmtx_unlock(rp_shmtx_t *mtx)
{
    if (mtx->spin != (rp_uint_t) -1) {
        rp_log_debug0(RP_LOG_DEBUG_CORE, rp_cycle->log, 0, "shmtx unlock");
    }

    if (rp_atomic_cmp_set(mtx->lock, rp_pid, 0)) {
        rp_shmtx_wakeup(mtx);
    }
}


rp_uint_t
rp_shmtx_force_unlock(rp_shmtx_t *mtx, rp_pid_t pid)
{
    rp_log_debug0(RP_LOG_DEBUG_CORE, rp_cycle->log, 0,
                   "shmtx forced unlock");

    if (rp_atomic_cmp_set(mtx->lock, pid, 0)) {
        rp_shmtx_wakeup(mtx);
        return 1;
    }

    return 0;
}


static void
rp_shmtx_wakeup(rp_shmtx_t *mtx)
{
#if (RP_HAVE_POSIX_SEM)
    rp_atomic_uint_t  wait;

    if (!mtx->semaphore) {
        return;
    }

    for ( ;; ) {

        wait = *mtx->wait;

        if ((rp_atomic_int_t) wait <= 0) {
            return;
        }

        if (rp_atomic_cmp_set(mtx->wait, wait, wait - 1)) {
            break;
        }
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, rp_cycle->log, 0,
                   "shmtx wake %uA", wait);

    if (sem_post(&mtx->sem) == -1) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_errno,
                      "sem_post() failed while wake shmtx");
    }

#endif
}


#else


rp_int_t
rp_shmtx_create(rp_shmtx_t *mtx, rp_shmtx_sh_t *addr, u_char *name)
{
    if (mtx->name) {

        if (rp_strcmp(name, mtx->name) == 0) {
            mtx->name = name;
            return RP_OK;
        }

        rp_shmtx_destroy(mtx);
    }

    mtx->fd = rp_open_file(name, RP_FILE_RDWR, RP_FILE_CREATE_OR_OPEN,
                            RP_FILE_DEFAULT_ACCESS);

    if (mtx->fd == RP_INVALID_FILE) {
        rp_log_error(RP_LOG_EMERG, rp_cycle->log, rp_errno,
                      rp_open_file_n " \"%s\" failed", name);
        return RP_ERROR;
    }

    if (rp_delete_file(name) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_errno,
                      rp_delete_file_n " \"%s\" failed", name);
    }

    mtx->name = name;

    return RP_OK;
}


void
rp_shmtx_destroy(rp_shmtx_t *mtx)
{
    if (rp_close_file(mtx->fd) == RP_FILE_ERROR) {
        rp_log_error(RP_LOG_ALERT, rp_cycle->log, rp_errno,
                      rp_close_file_n " \"%s\" failed", mtx->name);
    }
}


rp_uint_t
rp_shmtx_trylock(rp_shmtx_t *mtx)
{
    rp_err_t  err;

    err = rp_trylock_fd(mtx->fd);

    if (err == 0) {
        return 1;
    }

    if (err == RP_EAGAIN) {
        return 0;
    }

#if __osf__ /* Tru64 UNIX */

    if (err == RP_EACCES) {
        return 0;
    }

#endif

    rp_log_abort(err, rp_trylock_fd_n " %s failed", mtx->name);

    return 0;
}


void
rp_shmtx_lock(rp_shmtx_t *mtx)
{
    rp_err_t  err;

    err = rp_lock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    rp_log_abort(err, rp_lock_fd_n " %s failed", mtx->name);
}


void
rp_shmtx_unlock(rp_shmtx_t *mtx)
{
    rp_err_t  err;

    err = rp_unlock_fd(mtx->fd);

    if (err == 0) {
        return;
    }

    rp_log_abort(err, rp_unlock_fd_n " %s failed", mtx->name);
}


rp_uint_t
rp_shmtx_force_unlock(rp_shmtx_t *mtx, rp_pid_t pid)
{
    return 0;
}

#endif
