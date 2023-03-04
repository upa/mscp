#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#include <libgen.h>

#include <mscp.h>

/* message print. printed messages are passed to application via msg_fd */
void mprint_set_severity(int severity);
void mprint(int fd, int severity, const char *fmt, ...);

#define mpr_err(fd, fmt, ...)					\
	mprint(fd, MSCP_SEVERITY_ERR, fmt, ##__VA_ARGS__)
#define mpr_warn(fd, fmt, ...)					\
	mprint(fd, MSCP_SEVERITY_WARN, fmt, ##__VA_ARGS__)
#define mpr_notice(fd, fmt, ...)				\
	mprint(fd, MSCP_SEVERITY_NOTICE, fmt, ##__VA_ARGS__)
#define mpr_info(fd, fmt, ...)					\
	mprint(fd, MSCP_SEVERITY_INFO, fmt, ##__VA_ARGS__)
#define mpr_debug(fd, fmt, ...)					\
	mprint(fd, MSCP_SEVERITY_DEBUG, fmt, ##__VA_ARGS__)


/* error message buffer */
#define mscp_set_error(fmt, ...)					\
	_mscp_set_error("%s:%d:%s: " fmt,				\
			basename(__FILE__), __LINE__, __func__, ##__VA_ARGS__)

void _mscp_set_error(const char *fmt, ...);

#endif /* _MESSAGE_H_ */
