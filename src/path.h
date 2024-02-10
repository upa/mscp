/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _PATH_H_
#define _PATH_H_

#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <list.h>
#include <pool.h>
#include <atomic.h>
#include <ssh.h>

struct path {
	char *path; /* file path */
	size_t size; /* size of file on this path */
	mode_t mode; /* permission */

	char *dst_path; /* copy dst path */

	int state;
	lock lock;
	refcnt refcnt;
};
#define FILE_STATE_INIT 0
#define FILE_STATE_OPENED 1
#define FILE_STATE_DONE 2

struct chunk {
	struct list_head list; /* chunk_pool->list */

	struct path *p;
	size_t off; /* offset of this chunk on the file on path p */
	size_t len; /* length of this chunk */
	size_t done; /* copied bytes for this chunk by a thread */
};

struct chunk_pool {
	struct list_head list; /* list of struct chunk */
	size_t count;
	lock lock;
	int state;
};

/* initialize chunk pool */
void chunk_pool_init(struct chunk_pool *cp);

/* acquire a chunk from pool. return value is NULL indicates no more
 * chunk, GET_CHUNK_WAIT means caller should waits until a chunk is
 * added, or pointer to chunk.
 */
struct chunk *chunk_pool_pop(struct chunk_pool *cp);
#define CHUNK_POP_WAIT ((void *)-1)

/* set and check fillingchunks to this pool has finished */
void chunk_pool_set_filled(struct chunk_pool *cp);
bool chunk_pool_is_filled(struct chunk_pool *cp);

/* return number of chunks in the pool */
size_t chunk_pool_size(struct chunk_pool *cp);

/* return true if chunk pool is empty (all chunks are already poped) */
bool chunk_pool_is_empty(struct chunk_pool *cp);

/* free chunks in the chunk_pool */
void chunk_pool_release(struct chunk_pool *cp);

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
	struct chunk_pool *cp;
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
	       int nr_ahead, int buf_sz, bool preserve_ts, size_t *counter);

#endif /* _PATH_H_ */
