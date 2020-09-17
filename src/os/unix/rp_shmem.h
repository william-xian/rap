
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_SHMEM_H_INCLUDED_
#define _RP_SHMEM_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


typedef struct {
    u_char      *addr;
    size_t       size;
    rp_str_t    name;
    rp_log_t   *log;
    rp_uint_t   exists;   /* unsigned  exists:1;  */
} rp_shm_t;


rp_int_t rp_shm_alloc(rp_shm_t *shm);
void rp_shm_free(rp_shm_t *shm);


#endif /* _RP_SHMEM_H_INCLUDED_ */
