#include <stdio.h>
#include <stdarg.h>
#include <pthread.h>

static int pprint_level = 1;

static pthread_mutex_t pprint_lock = PTHREAD_MUTEX_INITIALIZER;

void pprint_set_level(int level)
{
	pprint_level = level;
}

void pprint(int level, const char *fmt, ...)
{
	va_list va;

	if (level <= pprint_level) {
		pthread_mutex_lock(&pprint_lock);
		va_start(va, fmt);
		vfprintf(stdout, fmt, va);
		fflush(stdout);
		va_end(va);
		pthread_mutex_unlock(&pprint_lock);
	}
}

