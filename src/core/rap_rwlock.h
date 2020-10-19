
/*
 * Copyright (C) Ruslan Ermilov
 * Copyright (C) Rap, Inc.
 */


#ifndef _RAP_RWLOCK_H_INCLUDED_
#define _RAP_RWLOCK_H_INCLUDED_


#include <rap_config.h>
#include <rap_core.h>


void rap_rwlock_wlock(rap_atomic_t *lock);
void rap_rwlock_rlock(rap_atomic_t *lock);
void rap_rwlock_unlock(rap_atomic_t *lock);
void rap_rwlock_downgrade(rap_atomic_t *lock);


#endif /* _RAP_RWLOCK_H_INCLUDED_ */
