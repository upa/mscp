#ifdef __APPLE__
#include <stdlib.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#elif linux
#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#else
#error unsupported platform
#endif

#include <util.h>
#include <platform.h>
#include <message.h>


#ifdef __APPLE__
int nr_cpus()
{
	int n;
	size_t size = sizeof(n);

	if (sysctlbyname("machdep.cpu.core_count", &n, &size, NULL, 0) != 0) {
		mscp_set_error("failed to get number of cpu cores: %s", strerrno());
		return -1;
	}

	return n;
}

int set_thread_affinity(pthread_t tid, int core)
{
	pr_warn("setting thread afinity is not implemented on apple\n");
	return 0;
}


static void random_string(char *buf, size_t size)
{
        char chars[] = "abcdefhijklmnopkwxyz1234567890";
        int n, x;

        for (n = 0; n < size - 1; n++) {
                x = arc4random(sizeof(chars) - 1);
                buf[n] = chars[x];
        }
        buf[size - 1] = '\0';

        return 0;
}

sem_t *sem_create(int value)
{
	char sem_name[PSEMNAMLEN] = "mscp-";
	sem_t *sem;
	int n;

        n = strlen(sem_name);
        random_string(sem_name + n, sizeof(sem_name) - n - 1);
        if ((sem = sem_open(sem_name, O_CREAT, 600, value)) == SEM_FAILED)
	    return NULL;

	return sem;
}

int sem_release(sem_t *sem)
{
	return sem_close(sem);
}

#endif

#ifdef linux
int nr_cpus()
{
	cpu_set_t cpu_set;
	if (sched_getaffinity(0, sizeof(cpu_set_t), &cpu_set) == 0)
		return CPU_COUNT(&cpu_set);
	return -1;
}

int set_thread_affinity(pthread_t tid, int core)
{
	cpu_set_t target_cpu_set;
	int ret = 0;

	CPU_ZERO(&target_cpu_set);
	CPU_SET(core, &target_cpu_set);
	ret = pthread_setaffinity_np(tid, sizeof(target_cpu_set), &target_cpu_set);
	if (ret < 0)
		mscp_set_error("failed to set thread/cpu affinity for core %d: %s",
			       core, strerrno());
	return ret;
}

sem_t *sem_create(int value)
{
	sem_t *sem;

	if ((sem = malloc(sizeof(*sem))) == NULL)
		return NULL;

	if (sem_init(sem, 0, value) < 0) {
		free(sem);
		return sem;
	}

	return sem;
}

int sem_release(sem_t *sem)
{
	int ret = sem_close(sem);
	free(sem);
	return ret;
}

#endif

