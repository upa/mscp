#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>

#include <util.h>
#include <message.h>

/* strerror_r wrapper */
__thread char thread_strerror[128];

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

static int mprint_severity = MSCP_SEVERITY_WARN;

void mprint_set_severity(int serverity)
{
	if (serverity < 0)
		mprint_severity = -1; /* no print */
	mprint_severity = serverity;
}

int mprint_get_severity()
{
	return mprint_severity;
}

