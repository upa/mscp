/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _BWLIMIT_H_
#define _BWLIMIT_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <semaphore.h>

struct bwlimit {
	sem_t		*sem;	/* semaphore */
	uint64_t	bps;	/* limit bit-rate (bps) */
	uint64_t	win;	/* window size (msec) */
	size_t		amt;	/* amount of bytes can be sent in a window */

	ssize_t		credit;	/* remaining bytes can be sent in a window */
	struct timespec wstart, wend; /* window start time and end time */
};

int bwlimit_init(struct bwlimit *bw, uint64_t bps, uint64_t win);
/* if bps is 0, it means that bwlimit is not active. If so,
 * bwlimit_wait() returns immediately. */

int bwlimit_wait(struct bwlimit *bw, size_t nr_bytes);


#endif /* _BWLIMIT_H_ */
