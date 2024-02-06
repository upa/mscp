/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _ATOMIC_H_
#define _ATOMIC_H_

#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

typedef int refcnt;

static inline void refcnt_inc(refcnt *cnt)
{
	__sync_add_and_fetch(cnt, 1);
}

static inline refcnt refcnt_dec(refcnt *cnt)
{
	return __sync_sub_and_fetch(cnt, 1);
}

/* mutex */

typedef pthread_mutex_t lock;

static inline void lock_init(lock *l)
{
	pthread_mutex_init(l, NULL);
}

static inline void lock_acquire(lock *l)
{
	int ret = pthread_mutex_lock(l);
	assert(ret == 0);
}

static inline void lock_release(lock *l)
{
	int ret = pthread_mutex_unlock(l);
	assert(ret == 0);
}

static inline void lock_release_via_cleanup(void *l)
{
	lock_release(l);
}

#define LOCK_ACQUIRE(l)  \
	lock_acquire(l); \
	pthread_cleanup_push(lock_release_via_cleanup, l)

#define LOCK_RELEASE() pthread_cleanup_pop(1)

/* read/write lock */
typedef pthread_rwlock_t rwlock;

static inline void rwlock_init(rwlock *rw)
{
	pthread_rwlock_init(rw, NULL);
}

static inline void rwlock_read_acquire(rwlock *rw)
{
	int ret = pthread_rwlock_rdlock(rw);
	assert(ret == 0);
}

static inline void rwlock_write_acquire(rwlock *rw)
{
	int ret = pthread_rwlock_wrlock(rw);
	assert(ret == 0);
}

static inline void rwlock_release(rwlock *rw)
{
	int ret = pthread_rwlock_unlock(rw);
	assert(ret == 0);
}

static inline void rwlock_release_via_cleanup(void *rw)
{
	rwlock_release(rw);
}

#define RWLOCK_READ_ACQUIRE(rw)  \
	rwlock_read_acquire(rw); \
	pthread_cleanup_push(rwlock_release_via_cleanup, rw)

#define RWLOCK_WRITE_ACQUIRE(rw)  \
	rwlock_write_acquire(rw); \
	pthread_cleanup_push(rwlock_release_via_cleanup, rw)

#define RWLOCK_RELEASE() pthread_cleanup_pop(1)

#endif /* _ATOMIC_H_ */
