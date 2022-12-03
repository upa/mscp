#ifndef _FILE_H_
#define _FILE_H_

#include <limits.h>
#include <pthread.h>
#include "libssh/libssh.h"
#include "libssh/sftp.h"

#include <list.h>
#include <atomic.h>

struct file {
	struct list_head        list;   /* mscp->file_list */

	char    src_path[PATH_MAX];	/* copy source path */
	bool    src_is_remote;		/* source is remote */
	size_t  size;			/* size of this file */

	char    dst_path[PATH_MAX];	/* copy destination path */
	bool    dst_is_remote;		/* destination is remote */

	int     state;  /* destination file state */
	lock    lock;   /* mutex to protect state */
	refcnt  refcnt; /* chunks referencing this file */
};
#define FILE_STATE_INIT         0
#define FILE_STATE_OPENED       1
#define FILE_STATE_DONE         2

#define strloc(is_remote) is_remote ? "(remote)" : "(local)"

/* Allocating chunk increments refcnt of the associating file.
 * Multiple threads copying files follows:
 *
 * acquire a chunk (inside a global lock)
 *
 * if the file state of the chunk is INIT:
 *     acquire the file lock
 * *         if file state is INIT:
 *             create directory if necessary
 *             open file with O_TRUNC and close.
 *             set file state OPENED.
 *             // only the first thread in the lock open the destination file
 *     release the file lock
 * endif
 *
 * copy the chunk to the destination.
 * decrement the refcnt of the file.
 *
 * if refcnt == 0:
 *     all chunks are copied.
 *     set the file state DONE, print something useful output.
 * endif
 */

struct chunk {
	struct list_head        list;   /* mscp->chunk_list */
	struct file *f;
	size_t  off;    /* offset of this chunk on the file f */
	size_t  len;    /* length of this chunk */
	size_t  done;   /* copied bytes for this chunk by a thread */
};

char *file_find_hostname(char *path);
bool file_has_hostname(char *path);

int file_fill(sftp_session sftp, struct list_head *file_list, char **src_array, int cnt,
	      char *dst);

int chunk_fill(struct list_head *file_list, struct list_head *chunk_list,
	       int nr_conn, int min_chunk_sz, int max_chunk_sz);

struct chunk *chunk_acquire(struct list_head *chunk_list);
int chunk_prepare(struct chunk *c, sftp_session sftp);
int chunk_copy(struct chunk *c, sftp_session sftp, int nr_ahead, int buf_sz,
	       size_t *counter);


#ifdef DEBUG
void file_dump(struct list_head *file_list);
void chunk_dump(struct list_head *chunk_list);
#endif


#endif /* _FILE_H_ */
