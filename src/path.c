/* SPDX-License-Identifier: GPL-3.0-only */
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>
#include <assert.h>

#include <ssh.h>
#include <minmax.h>
#include <fileops.h>
#include <atomic.h>
#include <path.h>
#include <strerrno.h>
#include <print.h>

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
		pr_err("dirname: %s", strerrno());
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
			ret = snprintf(dst_file_path, PATH_MAX, "%s/%s", a->dst_path,
				       a->src_path + offset);
		else
			ret = snprintf(dst_file_path, PATH_MAX, "%s", a->dst_path);
	}

	/* src is file, and dst is dir */
	if (!a->src_path_is_dir && a->dst_path_is_dir)
		ret = snprintf(dst_file_path, PATH_MAX, "%s/%s", a->dst_path,
			       a->src_path + offset);

	/* both are directory */
	if (a->src_path_is_dir && a->dst_path_is_dir)
		ret = snprintf(dst_file_path, PATH_MAX, "%s/%s", a->dst_path,
			       src_file_path + offset);

	/* dst path does not exist. change dir name to dst_path */
	if (a->src_path_is_dir && !a->dst_path_is_dir)
		ret = snprintf(dst_file_path, PATH_MAX, "%s/%s", a->dst_path,
			       src_file_path + strlen(a->src_path) + 1);

	if (ret >= PATH_MAX) {
		pr_warn("Too long path: %s", dst_file_path);
		return NULL;
	}

	pr_debug("file: %s -> %s", src_file_path, dst_file_path);

	return strndup(dst_file_path, PATH_MAX);
}

/* chunk preparation */
struct chunk *alloc_chunk(struct path *p, size_t off, size_t len)
{
	struct chunk *c;

	if (!(c = malloc(sizeof(*c)))) {
		pr_err("malloc %s", strerrno());
		return NULL;
	}
	memset(c, 0, sizeof(*c));

	c->p = p;
	c->off = off;
	c->len = len;
	c->state = CHUNK_STATE_INIT;
	refcnt_inc(&p->refcnt);
	return c;
}

static int resolve_chunk(struct path *p, size_t size, struct path_resolve_args *a)
{
	struct chunk *c;
	size_t chunk_sz, off, len;
	size_t remaind;

	if (a->max_chunk_sz)
		chunk_sz = a->max_chunk_sz;
	else {
		chunk_sz = (size / (a->nr_conn * 4)) & a->chunk_align;
		if (chunk_sz <= a->min_chunk_sz)
			chunk_sz = a->min_chunk_sz;
	}

	/* for (size = size; size > 0;) does not create a file (chunk)
         * when file size is 0. This do {} while (remaind > 0) creates
         * just open/close a 0-byte file.
         */
	remaind = size;
	do {
		off = size - remaind;
		len = remaind < chunk_sz ? remaind : chunk_sz;
		c = alloc_chunk(p, off, len);
		if (!c)
			return -1;

		remaind -= len;
		if (pool_push_lock(a->chunk_pool, c) < 0) {
			pr_err("pool_push_lock: %s", strerrno());
			return -1;
		}
	} while (remaind > 0);

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

struct path *alloc_path(char *path, char *dst_path)
{
	struct path *p;

	if (!(p = malloc(sizeof(*p)))) {
		pr_err("malloc: %s", strerrno());
		return NULL;
	}
	memset(p, 0, sizeof(*p));

	p->path = path;
	p->dst_path = dst_path;
	p->state = FILE_STATE_INIT;
	lock_init(&p->lock);
	p->data = 0;

	return p;
}

static int append_path(sftp_session sftp, const char *path, struct stat st,
		       struct path_resolve_args *a)
{
	struct path *p;
	char *src, *dst;

	if (!(src = strdup(path))) {
		pr_err("strdup: %s", strerrno());
		return -1;
	}

	if (!(dst = resolve_dst_path(src, a))) {
		free(src);
		return -1;
	}

	if (!(p = alloc_path(src, dst)))
		return -1;

	if (resolve_chunk(p, st.st_size, a) < 0)
		return -1; /* XXX: do not free path becuase chunk(s)
			    * was added to chunk pool already */

	if (pool_push_lock(a->path_pool, p) < 0) {
		pr_err("pool_push: %s", strerrno());
		goto free_out;
	}

	*a->total_bytes += st.st_size;

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
			       struct path_resolve_args *a)
{
	char next_path[PATH_MAX + 1];
	struct dirent *e;
	struct stat st;
	MDIR *d;
	int ret;

	if (mscp_stat(path, &st, sftp) < 0) {
		pr_err("stat: %s: %s", path, strerrno());
		return -1;
	}

	if (S_ISREG(st.st_mode)) {
		/* this path is regular file. it is to be copied */
		return append_path(sftp, path, st, a);
	}

	if (!S_ISDIR(st.st_mode))
		return 0; /* not a regular file and not a directory, skip it. */

	/* ok, this path is a directory. walk through it. */
	if (!(d = mscp_opendir(path, sftp))) {
		pr_err("opendir: %s: %s", path, strerrno());
		return -1;
	}

	for (e = mscp_readdir(d); e; e = mscp_readdir(d)) {
		if (check_path_should_skip(e->d_name))
			continue;

		ret = snprintf(next_path, PATH_MAX, "%s/%s", path, e->d_name);
		if (ret >= PATH_MAX) {
			pr_warn("Too long path: %s/%s", path, e->d_name);
			continue;
		}

		walk_path_recursive(sftp, next_path, a);
		/* do not stop even when walk_path_recursive returns
		 * -1 due to an unreadable file. go to a next
		 * file. Thus, do not pass error messages via
		 * priv_set_err() under walk_path_recursive.  Print
		 * the error with pr_err immediately.
		 */
	}

	mscp_closedir(d);

	return 0;
}

int walk_src_path(sftp_session src_sftp, const char *src_path,
		  struct path_resolve_args *a)
{
	return walk_path_recursive(src_sftp, src_path, a);
}

/* based on
 * https://stackoverflow.com/questions/2336242/recursive-mkdir-system-call-on-unix */
static int touch_dst_path(struct path *p, sftp_session sftp)
{
	/* XXX: should reflect the permission of the original directory? */
	mode_t mode = S_IRWXU | S_IRWXG | S_IRWXO;
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
				priv_set_errv("mscp_stat %s: not a directory", path);
				return -1; /* path exists, but not directory. */
			}
		}

		if (errno == ENOENT) {
			/* no file on the path. create directory. */
			if (mscp_mkdir(path, mode, sftp) < 0) {
				priv_set_errv("mscp_mkdir %s: %s", path, strerrno());
				return -1;
			}
		}
next:
		*needle = '/';
	}

	/* Do not set O_TRUNC here. Instead, do mscp_setstat() at the
	 * end. see https://bugzilla.mindrot.org/show_bug.cgi?id=3431 */
	f = mscp_open(p->dst_path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR, sftp);
	if (!f) {
		priv_set_errv("mscp_open %s: %s", p->dst_path, strerrno());
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
			goto out;
		}
		p->state = FILE_STATE_OPENED;
		pr_info("copy start: %s", p->path);
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

static int copy_chunk_l2r(struct chunk *c, int fd, sftp_file sf, int nr_ahead, int buf_sz,
			  struct bwlimit *bw, size_t *counter)
{
	ssize_t read_bytes, remaind, thrown;
	int idx, ret;
	struct {
		uint32_t id;
		ssize_t len;
	} reqs[nr_ahead];

	if (c->len == 0)
		return 0;

	remaind = thrown = c->len;
	for (idx = 0; idx < nr_ahead && thrown > 0; idx++) {
		reqs[idx].len = min(thrown, buf_sz);
		reqs[idx].len = sftp_async_write(sf, read_to_buf, reqs[idx].len, &fd,
						 &reqs[idx].id);
		if (reqs[idx].len < 0) {
			priv_set_errv("sftp_async_write: %s",
				      sftp_get_ssh_error(sf->sftp));
			return -1;
		}
		thrown -= reqs[idx].len;
		bwlimit_wait(bw, reqs[idx].len);
	}

	for (idx = 0; remaind > 0; idx = (idx + 1) % nr_ahead) {
		ret = sftp_async_write_end(sf, reqs[idx].id, 1);
		if (ret != SSH_OK) {
			priv_set_errv("sftp_async_write_end: %s",
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
			priv_set_errv("sftp_async_write: %s",
				      sftp_get_ssh_error(sf->sftp));
			return -1;
		}
		thrown -= reqs[idx].len;
		bwlimit_wait(bw, reqs[idx].len);
	}

	if (remaind < 0) {
		priv_set_errv("invalid remaind bytes %ld. "
			      "last async_write_end bytes %lu.",
			      remaind, reqs[idx].len);
		return -1;
	}

	return 0;
}

static int copy_chunk_r2l(struct chunk *c, sftp_file sf, int fd, int nr_ahead, int buf_sz,
			  struct bwlimit *bw, size_t *counter)
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
			priv_set_errv("sftp_async_read_begin: %d",
				      sftp_get_error(sf->sftp));
			return -1;
		}
		thrown -= reqs[idx].len;
		bwlimit_wait(bw, reqs[idx].len);
	}

	for (idx = 0; remaind > 0; idx = (idx + 1) % nr_ahead) {
		read_bytes = sftp_async_read(sf, buf, reqs[idx].len, reqs[idx].id);
		if (read_bytes == SSH_ERROR) {
			priv_set_errv("sftp_async_read: %d", sftp_get_error(sf->sftp));
			return -1;
		}

		if (thrown > 0) {
			reqs[idx].len = min(thrown, sizeof(buf));
			reqs[idx].id = sftp_async_read_begin(sf, reqs[idx].len);
			thrown -= reqs[idx].len;
			bwlimit_wait(bw, reqs[idx].len);
		}

		write_bytes = write(fd, buf, read_bytes);
		if (write_bytes < 0) {
			priv_set_errv("write: %s", strerrno());
			return -1;
		}

		if (write_bytes < read_bytes) {
			priv_set_errv("failed to write full bytes");
			return -1;
		}

		*counter += write_bytes;
		remaind -= read_bytes;
	}

	if (remaind < 0) {
		priv_set_errv("invalid remaind bytes %ld. last async_read bytes %ld. "
			      "last write bytes %ld",
			      remaind, read_bytes, write_bytes);
		return -1;
	}

	return 0;
}

static int _copy_chunk(struct chunk *c, mf *s, mf *d, int nr_ahead, int buf_sz,
		       struct bwlimit *bw, size_t *counter)
{
	if (s->local && d->remote) /* local to remote copy */
		return copy_chunk_l2r(c, s->local, d->remote, nr_ahead, buf_sz, bw,
				      counter);
	else if (s->remote && d->local) /* remote to local copy */
		return copy_chunk_r2l(c, s->remote, d->local, nr_ahead, buf_sz, bw,
				      counter);

	assert(false);
	return -1; /* not reached */
}

int copy_chunk(struct chunk *c, sftp_session src_sftp, sftp_session dst_sftp,
	       int nr_ahead, int buf_sz, bool preserve_ts, struct bwlimit *bw,
	       size_t *counter)
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
	if (!(s = mscp_open(c->p->path, flags, mode, src_sftp))) {
		priv_set_errv("mscp_open: %s: %s", c->p->path, strerrno());
		return -1;
	}
	if (mscp_lseek(s, c->off) < 0) {
		priv_set_errv("mscp_lseek: %s: %s", c->p->path, strerrno());
		return -1;
	}

	/* open dst */
	flags = O_WRONLY;
	mode = S_IRUSR | S_IWUSR;
	if (!(d = mscp_open(c->p->dst_path, flags, mode, dst_sftp))) {
		mscp_close(s);
		priv_set_errv("mscp_open: %s: %s", c->p->dst_path, strerrno());
		return -1;
	}
	if (mscp_lseek(d, c->off) < 0) {
		priv_set_errv("mscp_lseek: %s: %s", c->p->dst_path, strerrno());
		return -1;
	}

	c->state = CHUNK_STATE_COPING;
	pr_debug("copy chunk start: %s 0x%lx-0x%lx", c->p->path, c->off, c->off + c->len);

	ret = _copy_chunk(c, s, d, nr_ahead, buf_sz, bw, counter);

	pr_debug("copy chunk done: %s 0x%lx-0x%lx", c->p->path, c->off, c->off + c->len);

	mscp_close(d);
	mscp_close(s);
	if (ret < 0)
		return ret;

	if (refcnt_dec(&c->p->refcnt) == 0) {
		struct stat st;
		c->p->state = FILE_STATE_DONE;

		/* sync stat */
		if (mscp_stat(c->p->path, &st, src_sftp) < 0) {
			priv_set_errv("mscp_stat: %s: %s", c->p->path, strerrno());
			return -1;
		}
		if (mscp_setstat(c->p->dst_path, &st, preserve_ts, dst_sftp) < 0) {
			priv_set_errv("mscp_setstat: %s: %s", c->p->path, strerrno());
			return -1;
		}
		pr_info("copy done: %s", c->p->path);
	}

	if (ret == 0)
		c->state = CHUNK_STATE_DONE;

	return ret;
}
