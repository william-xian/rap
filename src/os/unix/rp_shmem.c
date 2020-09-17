
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#include <rp_config.h>
#include <rp_core.h>


#if (RP_HAVE_MAP_ANON)

rp_int_t
rp_shm_alloc(rp_shm_t *shm)
{
    shm->addr = (u_char *) mmap(NULL, shm->size,
                                PROT_READ|PROT_WRITE,
                                MAP_ANON|MAP_SHARED, -1, 0);

    if (shm->addr == MAP_FAILED) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno,
                      "mmap(MAP_ANON|MAP_SHARED, %uz) failed", shm->size);
        return RP_ERROR;
    }

    return RP_OK;
}


void
rp_shm_free(rp_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

#elif (RP_HAVE_MAP_DEVZERO)

rp_int_t
rp_shm_alloc(rp_shm_t *shm)
{
    rp_fd_t  fd;

    fd = open("/dev/zero", O_RDWR);

    if (fd == -1) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno,
                      "open(\"/dev/zero\") failed");
        return RP_ERROR;
    }

    shm->addr = (u_char *) mmap(NULL, shm->size, PROT_READ|PROT_WRITE,
                                MAP_SHARED, fd, 0);

    if (shm->addr == MAP_FAILED) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno,
                      "mmap(/dev/zero, MAP_SHARED, %uz) failed", shm->size);
    }

    if (close(fd) == -1) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno,
                      "close(\"/dev/zero\") failed");
    }

    return (shm->addr == MAP_FAILED) ? RP_ERROR : RP_OK;
}


void
rp_shm_free(rp_shm_t *shm)
{
    if (munmap((void *) shm->addr, shm->size) == -1) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno,
                      "munmap(%p, %uz) failed", shm->addr, shm->size);
    }
}

#elif (RP_HAVE_SYSVSHM)

#include <sys/ipc.h>
#include <sys/shm.h>


rp_int_t
rp_shm_alloc(rp_shm_t *shm)
{
    int  id;

    id = shmget(IPC_PRIVATE, shm->size, (SHM_R|SHM_W|IPC_CREAT));

    if (id == -1) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno,
                      "shmget(%uz) failed", shm->size);
        return RP_ERROR;
    }

    rp_log_debug1(RP_LOG_DEBUG_CORE, shm->log, 0, "shmget id: %d", id);

    shm->addr = shmat(id, NULL, 0);

    if (shm->addr == (void *) -1) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno, "shmat() failed");
    }

    if (shmctl(id, IPC_RMID, NULL) == -1) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno,
                      "shmctl(IPC_RMID) failed");
    }

    return (shm->addr == (void *) -1) ? RP_ERROR : RP_OK;
}


void
rp_shm_free(rp_shm_t *shm)
{
    if (shmdt(shm->addr) == -1) {
        rp_log_error(RP_LOG_ALERT, shm->log, rp_errno,
                      "shmdt(%p) failed", shm->addr);
    }
}

#endif
