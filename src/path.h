/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _PATH_H_
#define _PATH_H_

#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pool.h>
#include <atomic.h>
#include <ssh.h>
#include <bwlimit.h>

struct path {
	char *path; /* file path */
	char *dst_path; /* copy dst path */

	refcnt refcnt; /* number of associated chunks */
	lock lock;
	int state;
#define FILE_STATE_INIT 0
#define FILE_STATE_OPENED 1
#define FILE_STATE_DONE 2

	uint64_t data; /* used by other components, i.e., checkpoint */
};

struct path *alloc_path(char *path, char *dst_path);

struct chunk {
	struct path *p;
	size_t off; /* offset of this chunk on the file on path p */
	size_t len; /* length of this chunk */
	int state;
#define CHUNK_STATE_INIT 0
#define CHUNK_STATE_COPING 1
#define CHUNK_STATE_DONE 2
};

struct chunk *alloc_chunk(struct path *p, size_t off, size_t len);

struct path_resolve_args {
	size_t *total_bytes;

	/* args to resolve src path to dst path */
	const char *src_path;
	const char *dst_path;
	bool src_path_is_dir;
	bool dst_path_is_dir;
	bool dst_path_should_dir;

	/* args to resolve chunks for a path */
	pool *path_pool;
	pool *chunk_pool;
	int nr_conn;
	size_t min_chunk_sz;
	size_t max_chunk_sz;
	size_t chunk_align;
};

/* walk src_path recursivly and fill a->path_pool with found files */
int walk_src_path(sftp_session src_sftp, const char *src_path,
		  struct path_resolve_args *a);

/* free struct path */
void free_path(struct path *p);

/* copy a chunk. either src_sftp or dst_sftp is not null, and another is null */
int copy_chunk(struct chunk *c, sftp_session src_sftp, sftp_session dst_sftp,
	       int nr_ahead, int buf_sz, bool preserve_ts, struct bwlimit *bw,
	       size_t *counter);

#endif /* _PATH_H_ */
