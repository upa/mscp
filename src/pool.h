/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _POOL_H_
#define _POOL_H_

#include <stdbool.h>
#include <stddef.h>

#include <atomic.h>

/* A pool like a stack with an iterator walking from the bottom to the
 * top. The memory foot print for a pool never shrinks. Thus this is
 * not suitable for long-term uses. */

struct pool_struct {
	void **array;
	size_t len; /* length of array */
	size_t num; /* number of items in the array */
	size_t idx; /* index used dy iter */
	lock lock;
};

typedef struct pool_struct pool;

/* allocate a new pool */
pool *pool_new(void);

/* func type applied to each item in a pool */
typedef void (*pool_map_f)(void *v);

/* apply f, which free an item, to all items and set num to 0 */
void pool_zeroize(pool *p, pool_map_f f);

/* free pool->array and pool */
void pool_free(pool *p);

/* free pool->array and pool after applying f to all items in p->array */
void pool_destroy(pool *p, pool_map_f f);

#define pool_lock(p) LOCK_ACQUIRE(&(p->lock))
#define pool_unlock(p) LOCK_RELEASE()

/*
 * pool_push() pushes *v to pool *p. pool_push_lock() does this while
 * locking *p.
 */
int pool_push(pool *p, void *v);
int pool_push_lock(pool *p, void *v);

/*
 * pool_pop() pops the last *v pushed to *p. pool_pop_lock() does this
 * while locking *p.
 */
void *pool_pop(pool *p);
void *pool_pop_lock(pool *p);

/* pool_get() returns value indexed by idx */
void *pool_get(pool *p, unsigned int idx);

#define pool_size(p) ((p)->num)
#define pool_is_empty(p) (pool_size(p) == 0)

/*
 * pool->idx indicates next *v in an iteration. This has two
 * use-cases.
 *
 * (1) A simple list: just a single thread has a pool, and the thread
 * can call pool_iter_for_each() for the pool (not thread safe).
 *
 * (2) A thread-safe queue: one thread initializes the iterator for a
 * pool by pool_iter_init(). Then, multiple threads get a next *v
 * concurrently by pool_iter_next_lock(), which means dequeuing. At
 * this time, other thread can add new *v by pool_push_lock(), which
 * means enqueuing. During this, other threads must not intercept the
 * pool by pool_iter_* functions.
 */

#define pool_iter_init(p) (p->idx = 0)
void *pool_iter_next(pool *p);
void *pool_iter_next_lock(pool *p);

/* pool_iter_has_next_lock() returns true if pool_iter_next(_lock)
 * function will retrun a next value, otherwise false, which means
 * there is no more values in this iteration. */
bool pool_iter_has_next_lock(pool *p);

#define pool_iter_for_each(p, v) \
	pool_iter_init(p);       \
	for (v = pool_iter_next(p); v != NULL; v = pool_iter_next(p))

#define pool_for_each(p, v, idx) \
	idx = 0;                 \
	for (v = pool_get(p, idx); v != NULL; v = pool_get(p, ++idx))

#endif /* _POOL_H_ */
