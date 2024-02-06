/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _PRINT_H_
#define _PRINT_H_

#include <libgen.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <mscp.h>

/* message print. printed messages are passed to application via msg_fd */
void set_print_severity(int severity);
int get_print_severity();

#define __print(fp, severity, fmt, ...)					\
	do {								\
		if (severity <= get_print_severity()) {		\
			fprintf(fp, "\r\033[K" fmt "\n", ##__VA_ARGS__);	\
			fflush(fp);					\
		}							\
	} while (0)

#define pr_err(fmt, ...)					\
	__print(stderr, MSCP_SEVERITY_ERR, fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)					\
	__print(stderr, MSCP_SEVERITY_WARN, fmt, ##__VA_ARGS__)
#define pr_notice(fmt, ...)				\
	__print(stdout, MSCP_SEVERITY_NOTICE, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)					\
	__print(stdout, MSCP_SEVERITY_INFO, fmt, ##__VA_ARGS__)
#define pr_debug(fmt, ...)					\
	__print(stdout, MSCP_SEVERITY_DEBUG, fmt, ##__VA_ARGS__)

#endif /* _PRINT_H_ */
