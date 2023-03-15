#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include <pthread.h>

#ifndef PSEMNAMLEN	/* defined in macOS, but not in Linux */
#define PSEMNAMLEN	31
#endif

int nr_cpus(void);
int set_thread_affinity(pthread_t tid, int core);
int get_random(int max);

#endif /* _PLATFORM_H_ */
