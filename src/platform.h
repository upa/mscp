#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include <pthread.h>

int nr_cpus();
int set_thread_affinity(pthread_t tid, int core);

#endif /* _PLATFORM_H_ */
