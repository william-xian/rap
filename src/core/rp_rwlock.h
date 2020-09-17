
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Rap, Inc.
 */


#ifndef _RP_RWLOCK_H_INCLUDED_
#define _RP_RWLOCK_H_INCLUDED_


#include <rp_config.h>
#include <rp_core.h>


void rp_rwlock_wlock(rp_atomic_t *lock);
void rp_rwlock_rlock(rp_atomic_t *lock);
void rp_rwlock_unlock(rp_atomic_t *lock);
void rp_rwlock_downgrade(rp_atomic_t *lock);


#endif /* _RP_RWLOCK_H_INCLUDED_ */
