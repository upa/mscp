#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>

#include <message.h>

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
