/* SPDX-License-Identifier: GPL-3.0-only */
#ifdef __APPLE__
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/sysctl.h>
#elif linux
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#elif __FreeBSD__
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread_np.h>
#else
#error unsupported platform
#endif

#include <config.h>
#include <platform.h>
#include <strerrno.h>
#include <print.h>

#ifdef __APPLE__
int nr_cpus()
{
	int n;
	size_t size = sizeof(n);

	if (sysctlbyname("machdep.cpu.core_count", &n, &size, NULL, 0) != 0) {
		priv_set_errv("failed to get number of cpu cores: %s", strerrno());
		return -1;
	}

	return n;
}

int set_thread_affinity(pthread_t tid, int core)
{
	pr_warn("setting thread afinity is not implemented on apple");
	return 0;
}

int setutimes(const char *path, struct timespec atime, struct timespec mtime)
{
	struct timeval tv[2] = {
		{
			.tv_sec = atime.tv_sec,
			.tv_usec = atime.tv_nsec * 1000,
		},
		{
			.tv_sec = mtime.tv_sec,
			.tv_usec = mtime.tv_nsec * 1000,
		},
	};
	return utimes(path, tv);
}

static void random_string(char *buf, size_t size)
{
	char chars[] = "abcdefhijklmnopqrstuvwxyz1234567890";
	int n, x;

	for (n = 0; n < size - 1; n++) {
		x = arc4random() % (sizeof(chars) - 1);
		buf[n] = chars[x];
	}
	buf[size - 1] = '\0';
}

sem_t *sem_create(int value)
{
	char sem_name[30] = "mscp-";
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
#endif

#ifdef __FreeBSD__
int nr_cpus()
{
	long nr_cpus = sysconf(_SC_NPROCESSORS_ONLN);
	return nr_cpus;
}
#endif

#if defined(linux) || defined(__FreeBSD__)

int set_thread_affinity(pthread_t tid, int core)
{
	cpu_set_t target_cpu_set;
	int ret = 0;

	CPU_ZERO(&target_cpu_set);
	CPU_SET(core, &target_cpu_set);
	ret = pthread_setaffinity_np(tid, sizeof(target_cpu_set), &target_cpu_set);
	if (ret < 0)
		priv_set_errv("failed to set thread/cpu affinity for core %d: %s", core,
			      strerrno());
	return ret;
}

int setutimes(const char *path, struct timespec atime, struct timespec mtime)
{
	struct timespec ts[2] = { atime, mtime };
	int fd = open(path, O_WRONLY);
	int ret;

	if (fd < 0)
		return -1;
	ret = futimens(fd, ts);
	close(fd);
	return ret;
}

sem_t *sem_create(int value)
{
	sem_t *sem;

	if ((sem = malloc(sizeof(*sem))) == NULL)
		return NULL;

	if (sem_init(sem, 0, value) < 0) {
		free(sem);
		return NULL;
	}

	return sem;
}

int sem_release(sem_t *sem)
{
	free(sem);
	return 0;
}

#endif
