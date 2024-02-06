/* SPDX-License-Identifier: GPL-3.0-only */
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>
#include <assert.h>

#include <ssh.h>
#include <util.h>
#include <fileops.h>
#include <list.h>
#include <atomic.h>
#include <path.h>
#include <message.h>

/* chunk pool operations */
#define CHUNK_POOL_STATE_FILLING	0
#define CHUNK_POOL_STATE_FILLED		1

void chunk_pool_init(struct chunk_pool *cp)
{
	memset(cp, 0, sizeof(*cp));
	INIT_LIST_HEAD(&cp->list);
	lock_init(&cp->lock);
	cp->state = CHUNK_POOL_STATE_FILLING;
}

static void chunk_pool_add(struct chunk_pool *cp, struct chunk *c)
{
	LOCK_ACQUIRE(&cp->lock);
	list_add_tail(&c->list, &cp->list);
	cp->count += 1;
	LOCK_RELEASE();
}

void chunk_pool_set_filled(struct chunk_pool *cp)
{
	cp->state = CHUNK_POOL_STATE_FILLED;
}

bool chunk_pool_is_filled(struct chunk_pool *cp)
{
	return (cp->state == CHUNK_POOL_STATE_FILLED);
}

size_t chunk_pool_size(struct chunk_pool *cp)
{
	return cp->count;
}

bool chunk_pool_is_empty(struct chunk_pool *cp)
{
	return list_empty(&cp->list);
}

struct chunk *chunk_pool_pop(struct chunk_pool *cp)
{
	struct list_head *first;
	struct chunk *c = NULL;

	LOCK_ACQUIRE(&cp->lock);
	first = cp->list.next;
	if (list_empty(&cp->list)) {
		if (!chunk_pool_is_filled(cp))
			c = CHUNK_POP_WAIT;
		else
			c = NULL; /* no more chunks */
	} else {
		c = list_entry(first, struct chunk, list);
		list_del(first);
	}
	LOCK_RELEASE();

	/* return CHUNK_POP_WAIT would be a rare case, because it
	 * means copying over SSH is faster than traversing
	 * local/remote file paths.
	 */

	return c;
}

static void chunk_free(struct list_head *list)
{
        struct chunk *c;
        c = list_entry(list, typeof(*c), list);
        free(c);
}

void chunk_pool_release(struct chunk_pool *cp)
{
	list_free_f(&cp->list, chunk_free);
}

/* paths of copy source resoltion */
static char *resolve_dst_path(const char *src_file_path, struct path_resolve_args *a)
{
        char copy[PATH_MAX + 1], dst_file_path[PATH_MAX + 1];
        char *prefix;
        int offset;
	int ret;

        strncpy(copy, a->src_path, PATH_MAX);
        prefix = dirname(copy);
        if (!prefix) {
                mscp_set_error("dirname: %s", strerrno());
                return NULL;
        }

	offset = strlen(prefix) + 1;
	if (strlen(prefix) == 1) { /* corner cases */
		switch (prefix[0]) {
		case '.':
			offset = 0;
			break;
		case '/':
			offset = 1;
			break;
		}
	}

        if (!a->src_path_is_dir && !a->dst_path_is_dir) {
                /* src path is file. dst path is (1) file, or (2) does not exist.
                 * In the second case, we need to put src under the dst.
                 */
                if (a->dst_path_should_dir)
                        ret = snprintf(dst_file_path, PATH_MAX, "%s/%s",
				       a->dst_path, a->src_path + offset);
                else
                        ret = snprintf(dst_file_path, PATH_MAX, "%s", a->dst_path);
        }

        /* src is file, and dst is dir */
        if (!a->src_path_is_dir && a->dst_path_is_dir)
                ret = snprintf(dst_file_path, PATH_MAX, "%s/%s",
			       a->dst_path, a->src_path + offset);

        /* both are directory */
        if (a->src_path_is_dir && a->dst_path_is_dir)
                ret = snprintf(dst_file_path, PATH_MAX, "%s/%s",
			       a->dst_path, src_file_path + offset);

        /* dst path does not exist. change dir name to dst_path */
        if (a->src_path_is_dir && !a->dst_path_is_dir)
                ret = snprintf(dst_file_path, PATH_MAX, "%s/%s",
			       a->dst_path, src_file_path + strlen(a->src_path) + 1);

	if (ret >= PATH_MAX) {
		mpr_warn("Too long path: %s", dst_file_path);
		return NULL;
	}

        mpr_debug("file: %s -> %s", src_file_path, dst_file_path);

        return strndup(dst_file_path, PATH_MAX);
}

/* chunk preparation */
static struct chunk *alloc_chunk(struct path *p)
{
        struct chunk *c;

        if (!(c = malloc(sizeof(*c)))) {
                mscp_set_error("malloc %s", strerrno());
                return NULL;
        }
        memset(c, 0, sizeof(*c));

        c->p = p;
        c->off = 0;
        c->len = 0;
        refcnt_inc(&p->refcnt);
        return c;
}

static int resolve_chunk(struct path *p, struct path_resolve_args *a)
{
        struct chunk *c;
        size_t chunk_sz;
        size_t size;

        if (p->size <= a->min_chunk_sz)
                chunk_sz = p->size;
        else if (a->max_chunk_sz)
                chunk_sz = a->max_chunk_sz;
        else {
                chunk_sz = (p->size - (p->size % a->nr_conn)) / a->nr_conn;
                chunk_sz &= ~a->chunk_align; /* align with page_sz */
                if (chunk_sz <= a->min_chunk_sz)
                        chunk_sz = a->min_chunk_sz;
        }

        /* for (size = f->size; size > 0;) does not create a file
         * (chunk) when file size is 0. This do {} while (size > 0)
         * creates just open/close a 0-byte file.
         */
        size = p->size;
        do {
                c = alloc_chunk(p);
                if (!c)
                        return -1;
                c->off = p->size - size;
                c->len = size < chunk_sz ? size : chunk_sz;
                size -= c->len;
                chunk_pool_add(a->cp, c);
        } while (size > 0);

        return 0;
}

void free_path(struct path *p)
{
	if (p->path)
		free(p->path);
	if (p->dst_path)
		free(p->dst_path);
	free(p);
}

static int append_path(sftp_session sftp, const char *path, struct stat st,
		       struct list_head *path_list, struct path_resolve_args *a)
{
	struct path *p;

	if (!(p = malloc(sizeof(*p)))) {
		mscp_set_error("failed to allocate memory: %s", strerrno());
		return -1;
	}

	memset(p, 0, sizeof(*p));
	INIT_LIST_HEAD(&p->list);
	p->path = strndup(path, PATH_MAX);
	if (!p->path)
		goto free_out;
	p->size = st.st_size;
	p->mode = st.st_mode;
	p->state = FILE_STATE_INIT;
	lock_init(&p->lock);

	p->dst_path = resolve_dst_path(p->path, a);
	if (!p->dst_path)
		goto free_out;

	if (resolve_chunk(p, a) < 0)
		return -1; /* XXX: do not free path becuase chunk(s)
			    * was added to chunk pool already */

	list_add_tail(&p->list, path_list);
	*a->total_bytes += p->size;

	return 0;

free_out:
	free_path(p);
	return -1;
}

static bool check_path_should_skip(const char *path)
{               
        int len = strlen(path);
        if ((len == 1 && strncmp(path, ".", 1) == 0) ||
            (len == 2 && strncmp(path, "..", 2) == 0)) {
                return true;
        }
        return false; 
}

static int walk_path_recursive(sftp_session sftp, const char *path,
			       struct list_head *path_list, struct path_resolve_args *a)
{
	char next_path[PATH_MAX + 1];
	struct dirent *e;
	struct stat st;
	MDIR *d;
	int ret;

	if (mscp_stat(path, &st, sftp) < 0) {
		mpr_err("stat: %s: %s",  path, strerrno());
		return -1;
	}

	if (S_ISREG(st.st_mode)) {
		/* this path is regular file. it is to be copied */
		return append_path(sftp, path, st, path_list, a);
	}

	if (!S_ISDIR(st.st_mode))
		return 0; /* not a regular file and not a directory, skip it. */

	/* ok, this path is a directory. walk through it. */
	if (!(d = mscp_opendir(path, sftp))) {
		mpr_err("opendir: %s: %s", path, strerrno());
		return -1;
	}
	
	for (e = mscp_readdir(d); e; e = mscp_readdir(d)) {
		if (check_path_should_skip(e->d_name))
			continue;
		
		ret = snprintf(next_path, PATH_MAX, "%s/%s", path, e->d_name);
		if (ret >= PATH_MAX) {
			mpr_warn("Too long path: %s/%s", path, e->d_name);
			continue;
		}

		walk_path_recursive(sftp, next_path, path_list, a);
		/* do not stop even when walk_path_recursive returns
		 * -1 due to an unreadable file. go to a next file. */
	}

	mscp_closedir(d);

	return 0;
}

int walk_src_path(sftp_session src_sftp, const char *src_path,
		  struct list_head *path_list, struct path_resolve_args *a)
{
	return walk_path_recursive(src_sftp, src_path, path_list, a);
}

void path_dump(struct list_head *path_list)
{
	struct path *p;

	list_for_each_entry(p, path_list, list) {
		printf("src: %s %lu-byte\n", p->path, p->size);
		printf("dst: %s\n", p->dst_path);
	}
}
	


/* based on
 * https://stackoverflow.com/questions/2336242/recursive-mkdir-system-call-on-unix */
static int touch_dst_path(struct path *p, sftp_session sftp)
{
        /* XXX: should reflect the permission of the original directory? */
        mode_t mode =  S_IRWXU | S_IRWXG | S_IRWXO;
	struct stat st;
        char path[PATH_MAX];
        char *needle;
        int ret;
	mf *f;

        strncpy(path, p->dst_path, sizeof(path));

        /* mkdir -p.
	 * XXX: this may be slow when dst is the remote side. need speed-up. */
        for (needle = strchr(path + 1, '/'); needle; needle = strchr(needle + 1, '/')) {
                *needle = '\0';

		if (mscp_stat(path, &st, sftp) == 0) {
			if (S_ISDIR(st.st_mode))
				goto next; /* directory exists. go deeper */
			else {
				mscp_set_error("mscp_stat %s: not a directory", path);
				return -1; /* path exists, but not directory. */
			}
		}

		if (errno == ENOENT) {
			/* no file on the path. create directory. */
			if (mscp_mkdir(path, mode, sftp) < 0) {
				mscp_set_error("mscp_mkdir %s: %s", path, strerrno());
				return -1;
			}
		}
        next:
                *needle = '/';
        }

	/* Do not set O_TRUNC here. Instead, do mscp_setstat() at the
	 * end. see https://bugzilla.mindrot.org/show_bug.cgi?id=3431 */
	f = mscp_open(p->dst_path, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR, sftp);
	if (!f) {
		mscp_set_error("mscp_open %s: %s\n", p->dst_path, strerrno());
		return -1;
	}

	mscp_close(f);

        return 0;
}

static int prepare_dst_path(struct path *p, sftp_session dst_sftp)
{
	int ret = 0;

	LOCK_ACQUIRE(&p->lock);
	if (p->state == FILE_STATE_INIT) {
		if (touch_dst_path(p, dst_sftp) < 0) {
			ret = -1;
			mpr_err("failed to prepare dst path: %s", mscp_get_error());
			goto out;
		}
		p->state = FILE_STATE_OPENED;
		mpr_info("copy start: %s", p->path);
	}

out:
	LOCK_RELEASE();
	return ret;
}


/* functions for copy */

static ssize_t read_to_buf(void *ptr, size_t len, void *userdata)
{
        int fd = *((int *)userdata);
        return read(fd, ptr, len);
}

static int copy_chunk_l2r(struct chunk *c, int fd, sftp_file sf,
			  int nr_ahead, int buf_sz, size_t *counter)
{
        ssize_t read_bytes, remaind, thrown;
        int idx, ret;
        struct {
                uint32_t id;
                ssize_t  len;
        } reqs[nr_ahead];

        if (c->len == 0)
                return 0;

        remaind = thrown = c->len;
        for (idx = 0; idx < nr_ahead && thrown > 0; idx++) {
                reqs[idx].len = min(thrown, buf_sz);
                reqs[idx].len = sftp_async_write(sf, read_to_buf, reqs[idx].len, &fd,
                                                 &reqs[idx].id);
                if (reqs[idx].len < 0) {
                        mscp_set_error("sftp_async_write: %s or %s",
				       sftp_get_ssh_error(sf->sftp), strerrno());
                        return -1;
                }
                thrown -= reqs[idx].len;
        }

        for (idx = 0; remaind > 0; idx = (idx + 1) % nr_ahead) {
                ret = sftp_async_write_end(sf, reqs[idx].id, 1);
                if (ret != SSH_OK) {
                        mscp_set_error("sftp_async_write_end: %s",
				       sftp_get_ssh_error(sf->sftp));
                        return -1;
                }

                *counter += reqs[idx].len;
                remaind -= reqs[idx].len;

                if (remaind <= 0)
                        break;

                if (thrown <= 0)
                        continue;

                reqs[idx].len = min(thrown, buf_sz);
                reqs[idx].len = sftp_async_write(sf, read_to_buf, reqs[idx].len, &fd,
                                                 &reqs[idx].id);
                if (reqs[idx].len < 0) {
                        mscp_set_error("sftp_async_write: %s or %s",
				       sftp_get_ssh_error(sf->sftp), strerrno());
                        return -1;
                }
                thrown -= reqs[idx].len;
        }

        if (remaind < 0) {
                mscp_set_error("invalid remaind bytes %ld. "
			       "last async_write_end bytes %lu.",
			       remaind, reqs[idx].len);
                return -1;
        }

        return 0;

}

static int copy_chunk_r2l(struct chunk *c, sftp_file sf, int fd,
			  int nr_ahead, int buf_sz, size_t *counter)
{
        ssize_t read_bytes, write_bytes, remaind, thrown;
        char buf[buf_sz];
        int idx;
        struct {
                int id;
                ssize_t len;
        } reqs[nr_ahead];

        if (c->len == 0)
                return 0;

        remaind = thrown = c->len;

        for (idx = 0; idx < nr_ahead && thrown > 0; idx++) {
                reqs[idx].len = min(thrown, sizeof(buf));
                reqs[idx].id = sftp_async_read_begin(sf, reqs[idx].len);
                if (reqs[idx].id < 0) {
                        mscp_set_error("sftp_async_read_begin: %d",
				       sftp_get_error(sf->sftp));
                        return -1;
                }
                thrown -= reqs[idx].len;
        }

        for (idx = 0; remaind > 0; idx = (idx + 1) % nr_ahead) {
                read_bytes = sftp_async_read(sf, buf, reqs[idx].len, reqs[idx].id);
                if (read_bytes == SSH_ERROR) {
                        mscp_set_error("sftp_async_read: %d",
				       sftp_get_error(sf->sftp));
                        return -1;
                }

                if (thrown > 0) {
                        reqs[idx].len = min(thrown, sizeof(buf));
                        reqs[idx].id = sftp_async_read_begin(sf, reqs[idx].len);
                        thrown -= reqs[idx].len;
                }

                write_bytes = write(fd, buf, read_bytes);
                if (write_bytes < 0) {
                        mscp_set_error("write: %s", strerrno());
                        return -1;
                }

                if (write_bytes < read_bytes) {
                        mscp_set_error("failed to write full bytes");
                        return -1;
                }

                *counter += write_bytes;
                remaind -= read_bytes;
        }

        if (remaind < 0) {
                mscp_set_error("invalid remaind bytes %ld. last async_read bytes %ld. "
			       "last write bytes %ld",
			       remaind, read_bytes, write_bytes);
                return -1;
        }

        return 0;
}

static int _copy_chunk(struct chunk *c, mf *s, mf *d,
		       int nr_ahead, int buf_sz, size_t *counter)
{
	if (s->local && d->remote) /* local to remote copy */
		return copy_chunk_l2r(c, s->local, d->remote, nr_ahead, buf_sz, counter);
	else if (s->remote && d->local)  /* remote to local copy */
		return copy_chunk_r2l(c, s->remote, d->local, nr_ahead, buf_sz, counter);

	assert(false);
	return -1; /* not reached */
}

int copy_chunk(struct chunk *c, sftp_session src_sftp, sftp_session dst_sftp,
	       int nr_ahead, int buf_sz, bool preserve_ts, size_t *counter)
{
	mode_t mode;
	int flags;
	mf *s, *d;
	int ret;

	assert((src_sftp && !dst_sftp) || (!src_sftp && dst_sftp));

	if (prepare_dst_path(c->p, dst_sftp) < 0)
		return -1;

	/* open src */
        flags = O_RDONLY;
        mode = S_IRUSR;
	s = mscp_open(c->p->path, flags, mode, src_sftp);
	if (!s) {
		mscp_set_error("mscp_open: %s: %s", c->p->path, strerrno());
		return -1;
	}
	if (mscp_lseek(s, c->off) < 0) {
		mscp_set_error("mscp_lseek: %s: %s", c->p->path, strerrno());
		return -1;
	}

	/* open dst */
        flags = O_WRONLY;
        mode = S_IRUSR|S_IWUSR;
	d = mscp_open(c->p->dst_path, flags, mode, dst_sftp);
	if (!d) {
		mscp_close(s);
		mscp_set_error("mscp_open: %s: %s", c->p->dst_path, strerrno());
		return -1;
	}
	if (mscp_lseek(d, c->off) < 0) {
		mscp_set_error("mscp_lseek: %s: %s", c->p->dst_path, strerrno());
		return -1;
	}

	mpr_debug("copy chunk start: %s 0x%lx-0x%lx",
		  c->p->path, c->off, c->off + c->len);

	ret = _copy_chunk(c, s, d, nr_ahead, buf_sz, counter);

	mpr_debug("copy chunk done: %s 0x%lx-0x%lx",
		  c->p->path, c->off, c->off + c->len);


	mscp_close(d);
	mscp_close(s);
	if (ret < 0)
		return ret;

	if (refcnt_dec(&c->p->refcnt) == 0) {
		struct stat st;
		c->p->state = FILE_STATE_DONE;

		/* sync stat */
		if (mscp_stat(c->p->path, &st, src_sftp) < 0) {
			mpr_err("mscp_stat: %s: %s", c->p->path, strerrno());
			return -1;
		}
		if (mscp_setstat(c->p->dst_path, &st, preserve_ts, dst_sftp) < 0) {
			mpr_err("mscp_setstat: %s: %s", c->p->path, strerrno());
			return -1;
		}
		mpr_info("copy done: %s", c->p->path);
	}

	return ret;
}
