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
#include <pprint.h>


static int append_path(sftp_session sftp, const char *path, mstat s,
		       struct list_head *path_list)
{
	struct path *p;

	if (!(p = malloc(sizeof(*p)))) {
		pr_err("failed to allocate memory: %s\n", strerrno());
		return -1;
	}

	memset(p, 0, sizeof(*p));
	INIT_LIST_HEAD(&p->list);
	strncpy(p->path, path, PATH_MAX - 1);
	p->size = mstat_size(s);
	p->mode = mstat_mode(s);
	p->state = FILE_STATE_INIT;
	lock_init(&p->lock);
	list_add_tail(&p->list, path_list);

	return 0;
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
			       struct list_head *path_list)
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
		ret = append_path(sftp, path, s, path_list);
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
		if (check_path_should_skip(mdirent_name(e)))
			continue;
		
		if (strlen(path) + 1 + strlen(mdirent_name(e)) > PATH_MAX) {
			pr_err("too long path: %s/%s\n", path, mdirent_name(e));
			return -1;
		}
		snprintf(next_path, sizeof(next_path), "%s/%s", path, mdirent_name(e));
		ret = walk_path_recursive(sftp, next_path, path_list);
		if (ret < 0)
			return ret;
	}

	mscp_closedir(d);

	return 0;
}

int walk_src_path(sftp_session src_sftp, const char *src_path,
		  struct list_head *path_list)
{
	return walk_path_recursive(src_sftp, src_path, path_list);
}

static int src2dst_path(const char *src_path, const char *src_file_path,
			const char *dst_path, char *dst_file_path, size_t len,
			bool src_path_is_dir, bool dst_path_is_dir)
{
	char copy[PATH_MAX];
	char *prefix;
	int offset;

	strncpy(copy, src_path, PATH_MAX - 1);
	prefix = dirname(copy);
	if (!prefix) {
		pr_err("dirname: %s\n", strerrno());
		return -1;
	}
	if (strlen(prefix) == 1 && prefix[0] == '.')
		offset = 0;
	else
		offset = strlen(prefix) + 1;


	/* both are file */
	if (!src_path_is_dir && !dst_path_is_dir)
		strncpy(dst_file_path, dst_path, len);

	/* src is file, and dst is dir */
	if (!src_path_is_dir && dst_path_is_dir)
		snprintf(dst_file_path, len, "%s/%s", dst_path, src_path + offset);

	/* both are directory */
	if (src_path_is_dir && dst_path_is_dir)
		snprintf(dst_file_path, len, "%s/%s", dst_path, src_file_path + offset);

	/* dst path does not exist. change dir name to dst_path */
	if (src_path_is_dir && !dst_path_is_dir)
		snprintf(dst_file_path, len, "%s/%s",
			 dst_path, src_file_path + strlen(src_path) + 1);

	return 0;
}

int resolve_dst_path(const char *src_path, const char *dst_path,
		     struct list_head *path_list, bool src_is_dir, bool dst_is_dir)
{
	struct path *p;

	list_for_each_entry(p, path_list, list) {
		if (src2dst_path(src_path, p->path, dst_path, p->dst_path, PATH_MAX,
				 src_is_dir, dst_is_dir) < 0)
			return -1;
	}

	return 0;
}

void path_dump(struct list_head *path_list)
{
	struct path *p;

	list_for_each_entry(p, path_list, list) {
		printf("src: %s %lu-byte\n", p->path, p->size);
		printf("dst: %s\n", p->dst_path);
	}
}
	
/* chunk preparation */

static struct chunk *alloc_chunk(struct path *p)
{
        struct chunk *c;

        if (!(c = malloc(sizeof(*c)))) {
                pr_err("%s\n", strerrno());
                return NULL;
        }
        memset(c, 0, sizeof(*c));

        c->p = p;
        c->off = 0;
        c->len = 0;
        refcnt_inc(&p->refcnt);
        return c;
}

static int get_page_mask(void)
{
        long page_sz = sysconf(_SC_PAGESIZE);
        size_t page_mask = 0;
        int n;

        for (n = 0; page_sz > 0; page_sz >>= 1, n++) {
                page_mask <<= 1;
                page_mask |= 1;
        }

        return page_mask >> 1;
}

int resolve_chunk(struct list_head *path_list, struct list_head *chunk_list,
		  int nr_conn, int min_chunk_sz, int max_chunk_sz)
{
        struct chunk *c;
        struct path *p;
        size_t page_mask;
        size_t chunk_sz;
        size_t size;

        page_mask = get_page_mask();

        list_for_each_entry(p, path_list, list) {
                if (p->size <= min_chunk_sz)
                        chunk_sz = p->size;
                else if (max_chunk_sz)
                        chunk_sz = max_chunk_sz;
                else {
                        chunk_sz = (p->size - (p->size % nr_conn)) / nr_conn;
                        chunk_sz &= ~page_mask; /* align with page_sz */
                        if (chunk_sz <= min_chunk_sz)
                                chunk_sz = min_chunk_sz;
                }

                /* for (size = f->size; size > 0;) does not create a
                 * file (chunk) when file size is 0. This do {} while
                 * (size > 0) creates just open/close a 0-byte file.
                 */
                size = p->size;
                do {
                        c = alloc_chunk(p);
                        if (!c)
                                return -1;
                        c->off = p->size - size;
                        c->len = size < chunk_sz ? size : chunk_sz;
                        size -= c->len;
                        list_add_tail(&c->list, chunk_list);
                } while (size > 0);
        }

        return 0;
}

void chunk_dump(struct list_head *chunk_list)
{
	struct chunk *c;

	list_for_each_entry(c, chunk_list, list) {
		printf("chunk: %s 0x%lx-%lx bytes\n",
		       c->p->path, c->off, c->off + c->len);
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
	 * XXX: this may be  slow when dst is the remote side. need speed-up. */
        for (needle = strchr(path + 1, '/'); needle; needle = strchr(needle + 1, '/')) {
                *needle = '\0';

		mstat s;
		if (mscp_stat(path, &s, sftp) == 0) {
			if (mstat_is_dir(s))
				goto next; /* directory exists. go deeper */
			else
				return -1; /* path exists, but not directory. */
		}

		if (mscp_stat_check_err_noent(sftp) == 0) {
			/* no file on the path. create directory. */
			if (mscp_mkdir(path, mode, sftp) < 0) {
				pr_err("mkdir %s: %s", path, mscp_strerror(sftp));
				return -1;
			}
		}
        next:
                *needle = '/';
        }

        /* open file with O_TRUNC to set file size 0 */
        mode = O_WRONLY|O_CREAT|O_TRUNC;
	h = mscp_open(p->dst_path, mode, S_IRUSR|S_IWUSR, 0, sftp);
	if (mscp_open_is_failed(h)) {
		pr_err("open %s: %s\n", p->dst_path, mscp_strerror(sftp));
		return -1;
	}
	mscp_close(h);

        return 0;
}

int prepare_dst_path(struct path *p, sftp_session dst_sftp)
{
	int ret = 0;

	LOCK_ACQUIRE_THREAD(&p->lock);
	if (p->state == FILE_STATE_INIT) {
		if (touch_dst_path(p, dst_sftp) < 0) {
			ret = -1;
			goto out;
		}
		p->state = FILE_STATE_OPENED;
		pprint2("copy start: %s\n", p->path);
	}

out:
	LOCK_RELEASE_THREAD();
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
                        pr_err("sftp_async_write: %d or %s\n",
                               sftp_get_error(sf->sftp), strerrno());
                        return -1;
                }
                thrown -= reqs[idx].len;
        }

        for (idx = 0; remaind > 0; idx = (idx + 1) % nr_ahead) {
                ret = sftp_async_write_end(sf, reqs[idx].id, 1);
                if (ret != SSH_OK) {
                        pr_err("sftp_async_write_end: %d\n", sftp_get_error(sf->sftp));
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
                        pr_err("sftp_async_write: %d or %s\n",
                               sftp_get_error(sf->sftp), strerrno());
                        return -1;
                }
                thrown -= reqs[idx].len;
        }

        if (remaind < 0) {
                pr_err("invalid remaind bytes %ld. last async_write_end bytes %lu.",
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
                        pr_err("sftp_async_read_begin: %d\n",
                               sftp_get_error(sf->sftp));
                        return -1;
                }
                thrown -= reqs[idx].len;
        }

        for (idx = 0; remaind > 0; idx = (idx + 1) % nr_ahead) {
                read_bytes = sftp_async_read(sf, buf, reqs[idx].len, reqs[idx].id);
                if (read_bytes == SSH_ERROR) {
                        pr_err("sftp_async_read: %d\n", sftp_get_error(sf->sftp));
                        return -1;
                }

                if (thrown > 0) {
                        reqs[idx].len = min(thrown, sizeof(buf));
                        reqs[idx].id = sftp_async_read_begin(sf, reqs[idx].len);
                        thrown -= reqs[idx].len;
                }

                write_bytes = write(fd, buf, read_bytes);
                if (write_bytes < 0) {
                        pr_err("write: %s\n", strerrno());
                        return -1;
                }

                if (write_bytes < read_bytes) {
                        pr_err("failed to write full bytes\n");
                        return -1;
                }

                *counter += write_bytes;
                remaind -= read_bytes;
        }

        if (remaind < 0) {
                pr_err("invalid remaind bytes %ld. last async_read bytes %ld. "
                       "last write bytes %ld\n",
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

int copy_chunk(struct chunk *c, sftp_session src_sftp, sftp_session dst_sftp,
	       int nr_ahead, int buf_sz, size_t *counter)
{
	mode_t mode;
	int flags;
	mfh s, d;
	int ret;

	assert((src_sftp && !dst_sftp) || (!src_sftp && dst_sftp));

	if (prepare_dst_path(c->p, dst_sftp) < 0)
		return -1;

	/* open src */
        flags = O_RDONLY;
        mode = S_IRUSR;
	s = mscp_open(c->p->path, mode, flags, c->off, src_sftp);
	if (mscp_open_is_failed(s)) {
		mscp_close(d);
		return -1;
	}

	/* open dst */
        flags = O_WRONLY;
        mode = S_IRUSR|S_IWUSR;
	d = mscp_open(c->p->dst_path, mode, flags, c->off, dst_sftp);
	if (mscp_open_is_failed(d))
		return -1;

	ret = _copy_chunk(c, s, d, nr_ahead, buf_sz, counter);
	mscp_close(d);
	mscp_close(s);
	if (ret < 0)
		return ret;

	if (refcnt_dec(&c->p->refcnt) == 0) {
		c->p->state = FILE_STATE_DONE;
		mscp_chmod(c->p->path, c->p->mode, dst_sftp);
		pprint2("copy done: %s\n", c->p->path);
	}

	return ret;
}
