/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _STRERRNO_
#define _STRERRNO_

#include <libgen.h> /* basename() */

/**
 * strerrno() returns error message string corresponding to errno.
 * strerrno() is thread safe.
 */
const char *strerrno(void);

/**
 * priv_set_err() sets an error message into a thread-local private
 * buffer. This error message can be accessed via priv_get_err().
 *
 * The top-level function in a thread should print errors using
 * priv_get_err(), while lower-level functions should set error
 * messages using priv_set_err().
 */
void priv_set_err(const char *fmt, ...);

/**
 * priv_set_errv(), a wrapper for priv_set_err(), just adds filename,
 * line, and function name to the error message.
 */
#define priv_set_errv(fmt, ...)                                                      \
	priv_set_err("[%s:%d:%s] " fmt "\0", basename(__FILE__), __LINE__, __func__, \
		     ##__VA_ARGS__)

/**
 * priv_get_err() gets the error message sotred in the thread-local private buffer.
 */
const char *priv_get_err();

#endif /* _STRERRNO_ */
