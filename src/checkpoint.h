/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef _CHECKPOINT_H_
#define _CHECKPOINT_H_

#include <pool.h>

/* checkpoint_save() stores states to a checkponint file (pathname) */
int checkpoint_save(const char *pathname, int dir, const char *user, const char *remote,
		    pool *path_pool, pool *chunk_pool);

/* checkpoint_load_meta() reads a checkpoint file (pathname) and returns
 * remote host string to *remote and transfer direction to *dir.
 */
int checkpoint_load_remote(const char *pathname, char *remote, size_t len, int *dir);

/* checkpoint_load_paths() reads a checkpoint file (pathname) and
 * fills path_pool and chunk_pool.
 */
int checkpoint_load_paths(const char *pathname, pool *path_pool, pool *chunk_pool);

#endif /* _CHECKPOINT_H_ */
