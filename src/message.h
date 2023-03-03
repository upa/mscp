#ifndef _MESSAGE_H_
#define _MESSAGE_H_

#include <libgen.h>

enum {
	MSCP_SEVERITY_ERR = 0,
	MSCP_SEVERITY_WARN,
	MSCP_SEVERITY_NOTICE,
	MSCP_SEVERITY_INFO,
	MSCP_SEVERITY_DEBUG,
};

/* message print. printed messages are passed to application via msg_fd */
//void mprint_set_severity(int severity);
//void mprint(int severity, const char *fmt, ...);

#define mpr_err(fmt, ...) mprint(MSCP_SEVERITY_ERR, fmt, ##__VA_ARGS__)
#define mpr_warn(fmt, ...) mprint(MSCP_SEVERITY_WARN, fmt, ##__VA_ARGS__)
#define mpr_notice(fmt, ...) mprint(MSCP_SEVERITY_NOTICE, fmt, ##__VA_ARGS__)
#define mpr_info(fmt, ...) mprint(MSCP_SEVERITY_INFO, fmt, ##__VA_ARGS__)
#define mpr_debug(fmt, ...) mprint(MSCP_SEVERITY_DEBUG, fmt, ##__VA_ARGS__)


/* error message buffer */
#define mscp_set_error(fmt, ...)						\
	_mscp_set_error("%s:%d:%s: " fmt,				\
			basename(__FILE__), __LINE__, __func__, ##__VA_ARGS__)

void _mscp_set_error(const char *fmt, ...);

#endif /* _MESSAGE_H_ */
