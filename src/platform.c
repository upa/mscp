#include <util.h>
#include <platform.h>

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#elif linux
#else
#error unsupported platform
#endif


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

