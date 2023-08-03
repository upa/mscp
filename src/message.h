#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#include <libgen.h>
#include <stdio.h>

#include <mscp.h>

/* message print. printed messages are passed to application via msg_fd */
void mprint_set_severity(int severity);
int mprint_get_severity();

#define mprint(fp, severity, fmt, ...)				\
	do {							\
		if (fp && severity <= mprint_get_severity()) {	\
			fprintf(fp, fmt, ##__VA_ARGS__);	\
			fflush(fp);				\
		}						\
	} while (0)

#define mpr_err(fp, fmt, ...)					\
	mprint(fp, MSCP_SEVERITY_ERR, fmt, ##__VA_ARGS__)
#define mpr_warn(fp, fmt, ...)					\
	mprint(fp, MSCP_SEVERITY_WARN, fmt, ##__VA_ARGS__)
#define mpr_notice(fp, fmt, ...)				\
	mprint(fp, MSCP_SEVERITY_NOTICE, fmt, ##__VA_ARGS__)
#define mpr_info(fp, fmt, ...)					\
	mprint(fp, MSCP_SEVERITY_INFO, fmt, ##__VA_ARGS__)
#define mpr_debug(fp, fmt, ...)					\
	mprint(fp, MSCP_SEVERITY_DEBUG, fmt, ##__VA_ARGS__)


/* errorno wrapper */
extern __thread char thread_strerror[128];

#ifdef _GNU_SOURCE
/* GNU strerror_r */
#define strerrno()							\
	strerror_r(errno, thread_strerror, sizeof(thread_strerror))
#else
/* this macro assumes that strerror_r never fails. any good way? */
#define strerrno()							\
	(strerror_r(errno, thread_strerror, sizeof(thread_strerror))    \
	 ? thread_strerror : thread_strerror)
#endif



/* error message buffer */
#define mscp_set_error(fmt, ...)					\
	_mscp_set_error("%s:%d:%s: " fmt "\0",				\
			basename(__FILE__), __LINE__, __func__, ##__VA_ARGS__)

void _mscp_set_error(const char *fmt, ...);

#endif /* _MESSAGE_H_ */
