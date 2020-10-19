
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rap_config.h>
#include <rap_core.h>


#if (RAP_HAVE_MAP_ANON)

rap_int_t
rap_shm_alloc(rap_shm_t *shm)
{
    shm->addr = (u_char *) mmap(NULL, shm->size,
                                PROT_READ|PROT_WRITE,
                                MAP_ANON|MAP_SHARED, -1, 0);

    if (shm->addr == MAP_FAILED) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno,
                      "mmap(MAP_ANON|MAP_SHARED, %uz) failed", shm->size);
        return RAP_ERROR;
    }

    return RAP_OK;
}


void
rap_shm_free(rap_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

#elif (RAP_HAVE_MAP_DEVZERO)

rap_int_t
rap_shm_alloc(rap_shm_t *shm)
{
    rap_fd_t  fd;

    fd = open("/dev/zero", O_RDWR);

    if (fd == -1) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno,
                      "open(\"/dev/zero\") failed");
        return RAP_ERROR;
    }

    shm->addr = (u_char *) mmap(NULL, shm->size, PROT_READ|PROT_WRITE,
                                MAP_SHARED, fd, 0);

    if (shm->addr == MAP_FAILED) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno,
                      "mmap(/dev/zero, MAP_SHARED, %uz) failed", shm->size);
    }

    if (close(fd) == -1) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno,
                      "close(\"/dev/zero\") failed");
    }

    return (shm->addr == MAP_FAILED) ? RAP_ERROR : RAP_OK;
}


void
rap_shm_free(rap_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

#elif (RAP_HAVE_SYSVSHM)

#include <sys/ipc.h>
#include <sys/shm.h>


rap_int_t
rap_shm_alloc(rap_shm_t *shm)
{
    int  id;

    id = shmget(IPC_PRIVATE, shm->size, (SHM_R|SHM_W|IPC_CREAT));

    if (id == -1) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno,
                      "shmget(%uz) failed", shm->size);
        return RAP_ERROR;
    }

    rap_log_debug1(RAP_LOG_DEBUG_CORE, shm->log, 0, "shmget id: %d", id);

    shm->addr = shmat(id, NULL, 0);

    if (shm->addr == (void *) -1) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno, "shmat() failed");
    }

    if (shmctl(id, IPC_RMID, NULL) == -1) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno,
                      "shmctl(IPC_RMID) failed");
    }

    return (shm->addr == (void *) -1) ? RAP_ERROR : RAP_OK;
}


void
rap_shm_free(rap_shm_t *shm)
{
    if (shmdt(shm->addr) == -1) {
        rap_log_error(RAP_LOG_ALERT, shm->log, rap_errno,
                      "shmdt(%p) failed", shm->addr);
    }
}

#endif
