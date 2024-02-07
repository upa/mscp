/* SPDX-License-Identifier: GPL-3.0-only */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include <strerrno.h>

#define STRERRNO_TLS_BUFSIZ 128
__thread char tls_strerrno_buf[STRERRNO_TLS_BUFSIZ];

const char *strerrno(void)
{
	snprintf(tls_strerrno_buf, sizeof(tls_strerrno_buf), "%s", "strerror_r error");
	strerror_r(errno, tls_strerrno_buf, sizeof(tls_strerrno_buf));
	return tls_strerrno_buf;
}

#define PRIV_ERR_BUFSIZ (1 << 12)
__thread char priv_err_buf[PRIV_ERR_BUFSIZ], internal[PRIV_ERR_BUFSIZ];

void priv_set_err(const char *fmt, ...)
{
	va_list va;
	memset(internal, 0, sizeof(internal));
	va_start(va, fmt);
	vsnprintf(internal, sizeof(internal), fmt, va);
	va_end(va);
	snprintf(priv_err_buf, sizeof(priv_err_buf), "%s", internal);
}

const char *priv_get_err()
{
	return priv_err_buf;
}
