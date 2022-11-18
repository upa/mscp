#ifdef __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#elif linux
#define _GNU_SOURCE
#include <sched.h>
#else
#error unsupported platform
#endif

#include <util.h>
#include <platform.h>

#ifdef __APPLE__
int nr_cpus()
{
	int n;
	size_t size = sizeof(n);

	if (sysctlbyname("machdep.cpu.core_count", &n, &size, NULL, 0) != 0) {
		pr_err("failed to get number of cpu cores: %s\n", strerrno());
		return -1;
	}

	return n;
}

int set_thread_affinity(pthread_t tid, int core)
{
	pr_warn("setting thread afinity is not implemented on apple\n");
	return 0;
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
		pr_err("failed to set thread/cpu affinity for core %d: %s",
		       core, strerrno());
	return ret;
}
#endif

