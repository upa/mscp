#ifndef _OPENBSD_COMPAT_H
#define _OPENBSD_COMPAT_H

#include "config.h"

#ifndef HAVE_STRLCAT
size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#endif /* _OPENBSD_COMPAT_H_ */
