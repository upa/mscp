#ifndef _ATOMIC_H_
#define _ATOMIC_H_

#include <stdlib.h>
#include <pthread.h>
#include <util.h>

typedef int refcnt;

static inline void refcnt_inc(refcnt *cnt)
{
        __sync_add_and_fetch(cnt, 1);
}

static inline void refcnt_dec(refcnt *cnt)
{
        __sync_sub_and_fetch(cnt, 1);
}


typedef pthread_mutex_t lock;

static inline void lock_init(lock *l)
{
        pthread_mutex_init(l, NULL);
}

static inline void lock_acquire(lock *l)
{
        int ret = pthread_mutex_lock(l);
        if (ret < 0) {
                switch (ret) {
                case EINVAL:
                        pr_err("invalid mutex\n");
                        exit(1);
                case EDEADLK:
                        pr_err("a deadlock would occur\n");
                        exit(1);
                }
        }
}

static inline void lock_release(lock *l)
{
        int ret = pthread_mutex_unlock(l);
        if (ret < 0) {
                switch (ret) {
                case EINVAL:
                        pr_err("invalid mutex\n");
                        exit(1);
                case EPERM:
                        pr_err("this thread does not hold this mutex\n");
                        exit(1);
                }
        }
}

#endif /* _ATOMIC_H_ */
