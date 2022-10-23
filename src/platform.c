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

