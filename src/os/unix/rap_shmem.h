
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_SHMEM_H_INCLUDED_
#define _RAP_SHMEM_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


typedef struct {
    u_char      *addr;
    size_t       size;
    rap_str_t    name;
    rap_log_t   *log;
    rap_uint_t   exists;   /* unsigned  exists:1;  */
} rap_shm_t;


rap_int_t rap_shm_alloc(rap_shm_t *shm);
void rap_shm_free(rap_shm_t *shm);


#endif /* _RAP_SHMEM_H_INCLUDED_ */
