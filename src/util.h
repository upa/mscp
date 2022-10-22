#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <string.h>
#include <errno.h>

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

extern int verbose;

#define pr_v(level, fmt, ...) do {				\
		if (verbose >= level) {				\
			fprintf(stdout, "\x1b[1m\x1b[34m"	\
				"%s(): \x1b[0m" fmt,	\
				__func__, ##__VA_ARGS__);	\
		}						\
	} while (0)

#define pr_v1(fmt, ...) pr_v(1, fmt, ##__VA_ARGS__)
#define pr_v2(fmt, ...) pr_v(2, fmt, ##__VA_ARGS__)
#define pr_v3(fmt, ...) pr_v(3, fmt, ##__VA_ARGS__)


#define pr(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...) fprintf(stderr, "INFO:%s(): " fmt,    \
                                  __func__, ##__VA_ARGS__)

#define pr_warn(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[33m"	\
				  "WARN:%s():\x1b[0m " fmt,	\
				  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[31m"	\
				 "ERR:%s():\x1b[0m " fmt,	\
				 __func__, ##__VA_ARGS__)

#ifdef DEBUG
#define pr_debug(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[33m"    \
                                   "DEBUG:%s():\x1b[0m " fmt,	\
                                   __func__, ##__VA_ARGS__);
#else
#define pr_debug(fmt, ...)
#endif

#define strerrno() strerror(errno)

#endif /* _UTIL_H_ */
