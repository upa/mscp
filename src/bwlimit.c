/* SPDX-License-Identifier: GPL-3.0-only */
#include <errno.h>

#include <bwlimit.h>
#include <platform.h>

#define timespeczerorize(ts)    \
	do {                    \
		ts.tv_sec = 0;  \
		ts.tv_nsec = 0; \
	} while (0)

int bwlimit_init(struct bwlimit *bw, uint64_t bps, uint64_t win)
{
	if (!(bw->sem = sem_create(1)))
		return -1;

	bw->bps = bps;
	bw->win = win; /* msec window */
	bw->amt = (double)bps / 8 / 1000 * win; /* bytes in a window (msec) */
	bw->credit = bw->amt;
	timespeczerorize(bw->wstart);
	timespeczerorize(bw->wend);

	return 0;
}

#define timespecisset(ts) ((ts).tv_sec || (ts).tv_nsec)

#define timespecmsadd(a, msec, r)                                \
	do {                                                     \
		(r).tv_sec = (a).tv_sec;                         \
		(r).tv_nsec = (a).tv_nsec + (msec * 1000000);    \
		if ((r).tv_nsec > 1000000000) {                  \
			(r).tv_sec += (r.tv_nsec) / 1000000000L; \
			(r).tv_nsec = (r.tv_nsec) % 1000000000L; \
		}                                                \
	} while (0)

#define timespecsub(a, b, r)                             \
	do {                                             \
		(r).tv_sec = (a).tv_sec - (b).tv_sec;    \
		(r).tv_nsec = (a).tv_nsec - (b).tv_nsec; \
		if ((r).tv_nsec < 0) {                   \
			(r).tv_sec -= 1;                 \
			(r).tv_nsec += 1000000000;       \
		}                                        \
	} while (0)

#define timespeccmp(a, b, expr) \
	((a.tv_sec * 1000000000 + a.tv_nsec) expr(b.tv_sec * 1000000000 + b.tv_nsec))

#include <stdio.h>

int bwlimit_wait(struct bwlimit *bw, size_t nr_bytes)
{
	struct timespec now, end, rq, rm;

	if (bw->bps == 0)
		return 0; /* no bandwidth limit */

	if (sem_wait(bw->sem) < 0)
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &now);

	if (!timespecisset(bw->wstart)) {
		bw->wstart = now;
		timespecmsadd(bw->wstart, bw->win, bw->wend);
	}

	bw->credit -= nr_bytes;

	if (bw->credit < 0) {
		/* no more credit on this window. sleep until the end
		 * of this window + additional time for the remaining
		 * bytes. */
		uint64_t addition = (double)(bw->credit * -1) / (bw->bps / 8);
		timespecmsadd(bw->wend, addition * 1000, end);
		if (timespeccmp(end, now, >)) {
			timespecsub(end, now, rq);
			while (nanosleep(&rq, &rm) == -1) {
				if (errno != EINTR)
					break;
				rq = rm;
			}
		}
		bw->credit = bw->amt;
		timespeczerorize(bw->wstart);
	}

	sem_post(bw->sem);
	return 0;
}
