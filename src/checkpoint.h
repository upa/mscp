#ifndef _CHECKPOINT_H_
#define _CHECKPOINT_H_

#include <pool.h>

/* checkpoint_save() stores states to a checkponint file (pathname) */
int checkpoint_save(const char *pathname, int dir, char *remote_host, pool *path_pool,
		    pool *chunk_pool);

/* checkpoint_load() reads a checkpoint file (pathname). If path_pool
 * and chunk_pool are NULL, This function fills only *remote and *dir.
 */
int checkpoint_load(const char *pathname, char *remote, size_t len, int *dir,
		    pool *path_pool, pool *chunk_pool);

#endif /* _CHECKPOINT_H_ */
