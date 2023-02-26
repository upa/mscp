#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)


#define pr(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)

#define pr_info(fmt, ...) fprintf(stderr, "INFO:%s(): " fmt,    \
				  __func__, ##__VA_ARGS__)

#define pr_warn(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[33m"	\
				  "WARN:%s():\x1b[0m " fmt,	\
				  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[31m"	\
				 "ERR:%s:%d:%s():\x1b[0m " fmt,	\
				 basename(__FILE__), __LINE__, __func__, ##__VA_ARGS__)

#ifdef DEBUG
#define pr_debug(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[33m"    \
				   "DEBUG:%s():\x1b[0m " fmt,	\
				   __func__, ##__VA_ARGS__);
#else
#define pr_debug(fmt, ...)
#endif

#define strerrno() strerror(errno)


#define min(a, b) (((a) > (b)) ? (b) : (a))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#endif /* _UTIL_H_ */
