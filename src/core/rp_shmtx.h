
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_SHMTX_H_INCLUDED_
#define _RP_SHMTX_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct {
    rp_atomic_t   lock;
#if (RP_HAVE_POSIX_SEM)
    rp_atomic_t   wait;
#endif
} rp_shmtx_sh_t;


typedef struct {
#if (RP_HAVE_ATOMIC_OPS)
    rp_atomic_t  *lock;
#if (RP_HAVE_POSIX_SEM)
    rp_atomic_t  *wait;
    rp_uint_t     semaphore;
    sem_t          sem;
#endif
#else
    rp_fd_t       fd;
    u_char        *name;
#endif
    rp_uint_t     spin;
} rp_shmtx_t;


rp_int_t rp_shmtx_create(rp_shmtx_t *mtx, rp_shmtx_sh_t *addr,
    u_char *name);
void rp_shmtx_destroy(rp_shmtx_t *mtx);
rp_uint_t rp_shmtx_trylock(rp_shmtx_t *mtx);
void rp_shmtx_lock(rp_shmtx_t *mtx);
void rp_shmtx_unlock(rp_shmtx_t *mtx);
rp_uint_t rp_shmtx_force_unlock(rp_shmtx_t *mtx, rp_pid_t pid);


#endif /* _RP_SHMTX_H_INCLUDED_ */
