
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_SHMTX_H_INCLUDED_
#define _RAP_SHMTX_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct {
    rap_atomic_t   lock;
#if (RAP_HAVE_POSIX_SEM)
    rap_atomic_t   wait;
#endif
} rap_shmtx_sh_t;


typedef struct {
#if (RAP_HAVE_ATOMIC_OPS)
    rap_atomic_t  *lock;
#if (RAP_HAVE_POSIX_SEM)
    rap_atomic_t  *wait;
    rap_uint_t     semaphore;
    sem_t          sem;
#endif
#else
    rap_fd_t       fd;
    u_char        *name;
#endif
    rap_uint_t     spin;
} rap_shmtx_t;


rap_int_t rap_shmtx_create(rap_shmtx_t *mtx, rap_shmtx_sh_t *addr,
    u_char *name);
void rap_shmtx_destroy(rap_shmtx_t *mtx);
rap_uint_t rap_shmtx_trylock(rap_shmtx_t *mtx);
void rap_shmtx_lock(rap_shmtx_t *mtx);
void rap_shmtx_unlock(rap_shmtx_t *mtx);
rap_uint_t rap_shmtx_force_unlock(rap_shmtx_t *mtx, rap_pid_t pid);


#endif /* _RAP_SHMTX_H_INCLUDED_ */
