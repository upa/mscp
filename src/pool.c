/* SPDX-License-Identifier: GPL-3.0-only */
#include <string.h>
#include <stdlib.h>
#include <pool.h>

#define DEFAULT_START_SIZE 16

pool *pool_new(void)
{
	pool *p;
	p = malloc(sizeof(*p));
	if (!p)
		return NULL;
	memset(p, 0, sizeof(*p));

	p->array = calloc(DEFAULT_START_SIZE, sizeof(void *));
	if (!p->array) {
		free(p);
		return NULL;
	}

	p->len = DEFAULT_START_SIZE;
	p->num = 0;
	lock_init(&p->lock);
	return p;
}

void pool_free(pool *p)
{
	if (p->array) {
		free(p->array);
		p->array = NULL;
	}
	free(p);
}

void pool_zeroize(pool *p, pool_map_f f)
{
	void *v;
	pool_iter_for_each(p, v) {
		f(v);
	}
	p->num = 0;
}

void pool_destroy(pool *p, pool_map_f f)
{
	pool_zeroize(p, f);
	pool_free(p);
}

int pool_push(pool *p, void *v)
{
	if (p->num == p->len) {
		/* expand array */
		size_t newlen = p->len * 2;
		void *new = realloc(p->array, newlen * sizeof(void *));
		if (new == NULL)
			return -1;
		p->len = newlen;
		p->array = new;
	}
	p->array[p->num] = v;
	__sync_synchronize();
	p->num++;
	return 0;
}

int pool_push_lock(pool *p, void *v)
{
	int ret = -1;
	pool_lock(p);
	ret = pool_push(p, v);
	pool_unlock(p);
	return ret;
}

void *pool_pop(pool *p)
{
	return p->num == 0 ? NULL : p->array[--p->num];
}

void *pool_pop_lock(pool *p)
{
	void *v;
	pool_lock(p);
	v = pool_pop(p);
	pool_unlock(p);
	return v;
}

void *pool_get(pool *p, unsigned int idx)
{
	return p->num <= idx ? NULL : p->array[idx];
}

void *pool_iter_next(pool *p)
{
	if (p->num <= p->idx)
		return NULL;

	void *v = p->array[p->idx];
	p->idx++;
	return v;
}

void *pool_iter_next_lock(pool *p)
{
	void *v = NULL;
	pool_lock(p);
	v = pool_iter_next(p);
	pool_unlock(p);
	return v;
}

bool pool_iter_has_next_lock(pool *p)
{
	bool next_exist;
	pool_lock(p);
	next_exist = (p->idx < p->num);
	pool_unlock(p);
	return next_exist;
}
