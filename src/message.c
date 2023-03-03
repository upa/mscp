#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>

#include <message.h>

/* mscp error message buffer */

#define MSCP_ERRMSG_SIZE	(PATH_MAX * 2)

static char errmsg[MSCP_ERRMSG_SIZE];

void _mscp_set_error(const char *fmt, ...)
{
	va_list va;

	memset(errmsg, 0, sizeof(errmsg));
	va_start(va, fmt);
	vsnprintf(errmsg, sizeof(errmsg) - 1, fmt, va);
	va_end(va);
}

const char *mscp_get_error()
{
	return errmsg;
}


/* message print functions */

static int mprint_serverity = MSCP_SEVERITY_WARN;
static pthread_mutex_t mprint_lock = PTHREAD_MUTEX_INITIALIZER;

void mprint_set_severity(int serverity)
{
	if (serverity < 0)
		mprint_serverity = -1; /* no print */
	mprint_serverity = serverity;
}

void mprint(int fd, int serverity, const char *fmt, ...)
{
	va_list va;
	int ret;

	if (fd < 0)
		return;

	if (serverity <= mprint_serverity) {
		pthread_mutex_lock(&mprint_lock);
		va_start(va, fmt);
		vdprintf(fd, fmt, va);
		va_end(va);
		pthread_mutex_unlock(&mprint_lock);
	}
}
