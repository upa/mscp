#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include <pthread.h>
#include <semaphore.h>

int nr_cpus(void);
int set_thread_affinity(pthread_t tid, int core);

/*
 * macOS does not support sem_init(). macOS (seems to) releases the
 * named semaphore when associated mscp process finished. In linux,
 * program (seems to) need to release named semaphore in /dev/shm by
 * sem_unlink() explicitly. So, using sem_init() (unnamed semaphore)
 * in linux and using sem_open() (named semaphore) in macOS without
 * sem_unlink() are reasonable (?).
 */
sem_t *sem_create(int value);
int sem_release(sem_t *sem);

#endif /* _PLATFORM_H_ */
