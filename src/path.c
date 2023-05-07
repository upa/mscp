#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>
#include <assert.h>

#include <ssh.h>
#include <util.h>
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

	/* return CHUNK_POP_WAIT would be very rare case, because it
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
static int resolve_dst_path(const char *src_file_path, char *dst_file_path,
			    struct path_resolve_args *a)
{
        char copy[PATH_MAX];
        char *prefix;
        int offset;

        strncpy(copy, a->src_path, PATH_MAX - 1);
        prefix = dirname(copy);
        if (!prefix) {
                mscp_set_error("dirname: %s", strerrno());
                return -1;
        }
        if (strlen(prefix) == 1 && prefix[0] == '.')
                offset = 0;
        else
                offset = strlen(prefix) + 1;

        if (!a->src_path_is_dir && !a->dst_path_is_dir) {
                /* src path is file. dst path is (1) file, or (2) does not exist.
                 * In the second case, we need to put src under the dst.
                 */
                if (a->dst_path_should_dir)
                        snprintf(dst_file_path, PATH_MAX - 1, "%s/%s",
                                 a->dst_path, a->src_path + offset);
                else
                        strncpy(dst_file_path, a->dst_path, PATH_MAX - 1);
        }

        /* src is file, and dst is dir */
        if (!a->src_path_is_dir && a->dst_path_is_dir)
                snprintf(dst_file_path, PATH_MAX - 1, "%s/%s",
			 a->dst_path, a->src_path + offset);

        /* both are directory */
        if (a->src_path_is_dir && a->dst_path_is_dir)
                snprintf(dst_file_path, PATH_MAX - 1, "%s/%s",
			 a->dst_path, src_file_path + offset);

        /* dst path does not exist. change dir name to dst_path */
        if (a->src_path_is_dir && !a->dst_path_is_dir)
                snprintf(dst_file_path, PATH_MAX - 1, "%s/%s",
                         a->dst_path, src_file_path + strlen(a->src_path) + 1);

        mpr_debug(a->msg_fp, "file: %s -> %s\n", src_file_path, dst_file_path);

        return 0;
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

static int append_path(sftp_session sftp, const char *path, mstat s,
		       struct list_head *path_list, struct path_resolve_args *a)
{
	struct path *p;

	if (!(p = malloc(sizeof(*p)))) {
		mscp_set_error("failed to allocate memory: %s", strerrno());
		return -1;
	}

	memset(p, 0, sizeof(*p));
	INIT_LIST_HEAD(&p->list);
	strncpy(p->path, path, PATH_MAX - 1);
	p->size = mstat_size(s);
	p->mode = mstat_mode(s);
	p->state = FILE_STATE_INIT;
	lock_init(&p->lock);

	if (resolve_dst_path(p->path, p->dst_path, a) < 0)
		goto free_out;

	if (resolve_chunk(p, a) < 0)
		return -1; /* XXX: do not free path becuase chunk(s)
			    * was added to chunk pool already */

	list_add_tail(&p->list, path_list);
	*a->total_bytes += p->size;

	return 0;

free_out:
	free(p);
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
	char next_path[PATH_MAX];
	mdirent *e;
	mdir *d;
	mstat s;
	int ret;

	if (mscp_stat(path, &s, sftp) < 0)
		return -1;

	if (mstat_is_regular(s)) {
		/* this path is regular file. it is to be copied */
		ret = append_path(sftp, path, s, path_list, a);
		mscp_stat_free(s);
		return ret;
	}

	if (!mstat_is_dir(s)) {
		/* not regular file and not directory, skip it. */
		mscp_stat_free(s);
		return 0; 
	}

	mscp_stat_free(s);


	/* ok, this path is directory. walk it. */
	if (!(d = mscp_opendir(path, sftp)))
		return -1;
	
	for (e = mscp_readdir(d); !mdirent_is_null(e); e = mscp_readdir(d)) {
		if (check_path_should_skip(mdirent_name(e))) {
			mscp_dirent_free(e);
			continue;
		}
		
		if (strlen(path) + 1 + strlen(mdirent_name(e)) > PATH_MAX) {
			mscp_set_error("too long path: %s/%s", path, mdirent_name(e));
			mscp_dirent_free(e);
			return -1;
		}
		snprintf(next_path, sizeof(next_path), "%s/%s", path, mdirent_name(e));
		ret = walk_path_recursive(sftp, next_path, path_list, a);
		mscp_dirent_free(e);
		if (ret < 0)
			return ret;
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
        char path[PATH_MAX];
        char *needle;
        int ret;
	mfh h;

        strncpy(path, p->dst_path, sizeof(path));

        /* mkdir -p.
	 * XXX: this may be slow when dst is the remote side. need speed-up. */
        for (needle = strchr(path + 1, '/'); needle; needle = strchr(needle + 1, '/')) {
                *needle = '\0';

		mstat s;
		if (mscp_stat(path, &s, sftp) == 0) {
			if (mstat_is_dir(s)) {
				mscp_stat_free(s);
				goto next; /* directory exists. go deeper */
			} else {
				mscp_stat_free(s);
				return -1; /* path exists, but not directory. */
			}
		}

		if (mscp_stat_check_err_noent(sftp) == 0) {
			/* no file on the path. create directory. */
			if (mscp_mkdir(path, mode, sftp) < 0) {
				mscp_set_error("mkdir %s: %s", path,
					       mscp_strerror(sftp));
				return -1;
			}
		}
        next:
                *needle = '/';
        }

        /* open file with O_TRUNC to set file size 0 */
	h = mscp_open(p->dst_path, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR, 0, sftp);
	if (mscp_open_is_failed(h))
		return -1;

	mscp_close(h);

        return 0;
}

static int prepare_dst_path(FILE *msg_fp, struct path *p, sftp_session dst_sftp)
{
	int ret = 0;

	LOCK_ACQUIRE(&p->lock);
	if (p->state == FILE_STATE_INIT) {
		if (touch_dst_path(p, dst_sftp) < 0) {
			ret = -1;
			goto out;
		}
		p->state = FILE_STATE_OPENED;
		mpr_info(msg_fp, "copy start: %s\n", p->path);
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

static int _copy_chunk(struct chunk *c, mfh s, mfh d,
		       int nr_ahead, int buf_sz, size_t *counter)
{
	if (s.fd > 0 && d.sf) /* local to remote copy */
		return copy_chunk_l2r(c, s.fd, d.sf, nr_ahead, buf_sz, counter);
	else if (s.sf && d.fd > 0)  /* remote to local copy */
		return copy_chunk_r2l(c, s.sf, d.fd, nr_ahead, buf_sz, counter);

	assert(true); /* not reached */
	return -1;
}

int copy_chunk(FILE *msg_fp, struct chunk *c,
	       sftp_session src_sftp, sftp_session dst_sftp,
	       int nr_ahead, int buf_sz, size_t *counter)
{
	mode_t mode;
	int flags;
	mfh s, d;
	int ret;

	assert((src_sftp && !dst_sftp) || (!src_sftp && dst_sftp));

	if (prepare_dst_path(msg_fp, c->p, dst_sftp) < 0)
		return -1;

	/* open src */
        flags = O_RDONLY;
        mode = S_IRUSR;
	s = mscp_open(c->p->path, flags, mode, c->off, src_sftp);
	if (mscp_open_is_failed(s)) {
		mscp_close(d);
		return -1;
	}

	/* open dst */
        flags = O_WRONLY;
        mode = S_IRUSR|S_IWUSR;
	d = mscp_open(c->p->dst_path, flags, mode, c->off, dst_sftp);
	if (mscp_open_is_failed(d))
		return -1;

	mpr_debug(msg_fp, "copy chunk start: %s 0x%lx-0x%lx\n",
		  c->p->path, c->off, c->off + c->len);
	ret = _copy_chunk(c, s, d, nr_ahead, buf_sz, counter);

	mpr_debug(msg_fp, "copy chunk done: %s 0x%lx-0x%lx\n",
		  c->p->path, c->off, c->off + c->len);


	mscp_close(d);
	mscp_close(s);
	if (ret < 0)
		return ret;

	if (refcnt_dec(&c->p->refcnt) == 0) {
		c->p->state = FILE_STATE_DONE;
		mscp_chmod(c->p->dst_path, c->p->mode, dst_sftp);
		mpr_info(msg_fp, "copy done: %s\n", c->p->path);
	}

	return ret;
}
