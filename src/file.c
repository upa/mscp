#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>

#include <ssh.h>
#include <util.h>
#include <file.h>
#include <pprint.h>
#include <platform.h>

bool file_has_hostname(char *path)
{
	char *p;

	p = strchr(path, ':');
	if (p) {
		if (p == path || ((p > path) && *(p - 1) == '\\'))
			return false; /* first byte is colon or escaped colon, skip */
		else
			return true;
	}

	return false;
}

char *file_find_hostname(char *path)
{
	char *dup, *p;

	dup = strdup(path);
	if (!dup) {
		pr_err("%s", strerrno());
		return NULL;
	}

	p = strchr(dup, ':');
	if (p) {
		if (p == dup || ((p > dup) && *(p - 1) == '\\')) {
			/* first byte is colon or escaped colon, skip */
			free(dup);
		} else {
			/* handle this as remote hostname (with username) */
			*p = '\0';
			return dup;
		}
	}

	return NULL;
}

static char *file_find_path(char *path)
{
	char *p;

	p = strchr(path, ':');
	if (p) {
		if (p == path || ((p > path) && *(p - 1) == '\\')) {
			/* first byte is colon or escaped colon, skip */
			return path;
		} else {
			return p + 1;
		}
	}

	return path;
}

/* return 1 when path is directory, 0 is not directory, and -1 on error */
static int file_is_directory(char *path, sftp_session sftp, bool print_error)
{
	int ret = 0;

	if (sftp) {
		char *remote_path = file_find_path(path);
		sftp_attributes attr;

		char *p = *remote_path == '\0' ? "." : remote_path;
		attr = sftp_stat(sftp, p);
		if (!attr) {
			if (print_error)
				pr_err("sftp_stat %s: %s\n",
				       path, sftp_get_ssh_error(sftp));
			ret = -1;
		} else if (attr->type == SSH_FILEXFER_TYPE_DIRECTORY)
			ret = 1;
		sftp_attributes_free(attr);
	} else {
		struct stat statbuf;
		if (stat(path, &statbuf) < 0) {
			if (print_error)
				pr_err("stat %s: %s\n", path, strerrno());
			ret = -1;
		} else if (S_ISDIR(statbuf.st_mode))
			ret = 1;
	}

	return ret;
}

/* return 1 when directory exists, 0 not exists, and -1 on error */
int file_directory_exists(char *path, sftp_session sftp)
{
	int ret = 0;

	if (sftp) {
		sftp_attributes attr;
		attr = sftp_stat(sftp, path);
		if (!attr) {
			if (sftp_get_error(sftp) == SSH_FX_NO_SUCH_PATH ||
			    sftp_get_error(sftp) == SSH_FX_NO_SUCH_FILE)
				ret = 0;
			else {
				pr_err("%s: %s\n", path, sftp_get_ssh_error(sftp));
				ret = -1;
			}
		} else if (attr->type == SSH_FILEXFER_TYPE_DIRECTORY)
			ret = 1;
		sftp_attributes_free(attr);
	} else {
		struct stat statbuf;
		if (stat(path, &statbuf) < 0) {
			if (errno == ENOENT)
				ret = 0;
			else {
				pr_err("%s: %s\n", path, strerrno());
				ret = -1;
			}
		} else if ((statbuf.st_mode & S_IFMT) == S_IFDIR)
			ret = 1;
	}

	return ret;
}

static struct file *file_alloc(char *src_path, size_t size, bool src_is_remote)
{
	struct file *f;

	f = malloc(sizeof(*f));
	if (!f) {
		pr_err("%s\n", strerrno());
		return NULL;
	}
	memset(f, 0, sizeof(*f));

	strncpy(f->src_path, src_path, PATH_MAX - 1);
	f->size = size;
	f->src_is_remote = src_is_remote;
	f->dst_is_remote = !src_is_remote;
	lock_init(&f->lock);

	return f;
}

static bool check_file_should_skip(char *path)
{
	int len = strlen(path);
	if ((len == 1 && strncmp(path, ".", 1) == 0) ||
	    (len == 2 && strncmp(path, "..", 2) == 0)) {
		return true;
	}
	return false;
}


/* return -1 when error, 0 when should skip, and 1 when should be copied  */
static int check_file_tobe_copied(char *path, sftp_session sftp, size_t *size)
{
	struct stat statbuf;
	sftp_attributes attr;
	int ret = 0;

	if (!sftp) {
		/* local */
		if (stat(path, &statbuf) < 0) {
			pr_err("stat %s: %s\n", path, strerrno());
			return -1;
		}
		if (S_ISREG(statbuf.st_mode)) {
			*size = statbuf.st_size;
			return 1;
		}
		return 0;
	}

	/* remote */
	attr = sftp_stat(sftp, path);
	if (!attr) {
		pr_err("sftp_stat %s: %s\n", path, sftp_get_ssh_error(sftp));
		return -1;
	}
	if (attr->type == SSH_FILEXFER_TYPE_REGULAR ||
	    attr->type == SSH_FILEXFER_TYPE_SYMLINK) {
		*size = attr->size;
		ret = 1;
	}

	sftp_attributes_free(attr);

	return ret;
}

static int check_pathlen(const char *src, const char *dst)
{
	if ((strlen(src) + strlen(dst) + 1) > PATH_MAX) {
		pr_err("too long path: %s/%s\n", src, dst);
		return -1;
	}
	return 0;
}

static int file_fill_recursive(struct list_head *file_list,
			       bool dst_is_remote, sftp_session sftp, char *src_path,
			       char *rel_path, char *dst_path,
			       bool dst_should_dir, bool replace_dir_name)
{
	char next_src_path[PATH_MAX], next_rel_path[PATH_MAX];
	struct file *f;
	size_t size;
	int ret;

	ret = file_is_directory(src_path, dst_is_remote ? NULL : sftp, true);
	if (ret < 0)
		return -1;

	if (ret == 0) {
		/* src_path is file */
		ret = check_file_tobe_copied(src_path, dst_is_remote ? NULL : sftp,
					     &size);
		if (ret <= 0)
			return ret; /* error or skip */

		if ((f = file_alloc(src_path, size, !dst_is_remote)) == NULL) {
			pr_err("%s\n", strerrno());
			return -1;
		}

		if (dst_should_dir)
			snprintf(f->dst_path, PATH_MAX, "%s/%s%s",
				 dst_path, rel_path, basename(src_path));
		else
			snprintf(f->dst_path, PATH_MAX, "%s%s", rel_path, dst_path);

		list_add_tail(&f->list, file_list);
		pprint2("file %s %s -> %s %s %luB\n",
			f->src_path, dst_is_remote ? "(local)" : "(remote)",
			f->dst_path, dst_is_remote ? "(remote)" : "(local)",
			f->size);

		return 0;
	}

	/* src_path is directory */
	if (dst_is_remote) {
		/* src_path is local directory */
		struct dirent *de;
		DIR *dir;
		if ((dir = opendir(src_path)) == NULL) {
			pr_err("opendir '%s': %s\n", src_path, strerrno());
			return -1;
		}
		while ((de = readdir(dir)) != NULL) {
			if (check_file_should_skip(de->d_name))
				continue;
			if (check_pathlen(src_path, de->d_name) < 0 ||
			    check_pathlen(rel_path, basename(src_path)) < 0)
				return -1;

			snprintf(next_src_path, sizeof(next_src_path),
				 "%s/%s", src_path, de->d_name);
			if (replace_dir_name)
				memset(next_rel_path, 0, sizeof(next_rel_path));
			else
				snprintf(next_rel_path, sizeof(next_rel_path),
					 "%s%s/", rel_path, basename(src_path));
			ret = file_fill_recursive(file_list, dst_is_remote, sftp,
						  next_src_path, next_rel_path,
						  dst_path, dst_should_dir, false);
			if (ret < 0)
				return ret;
		}
	} else {
		/* src_path is remote directory */
		sftp_attributes attr;
		sftp_dir dir;
		if ((dir = sftp_opendir(sftp, src_path)) == NULL) {
			pr_err("sftp_opendir: '%s': %s\n", src_path,
			       sftp_get_ssh_error(sftp));
			return -1;
		}
		while ((attr = sftp_readdir(sftp, dir)) != NULL) {
			if (check_file_should_skip(attr->name))
				continue;
			if (check_pathlen(src_path, attr->name) < 0 ||
			    check_pathlen(rel_path, basename(src_path)) < 0)
				return -1;

			snprintf(next_src_path, sizeof(next_src_path),
				 "%s/%s", src_path, attr->name);
			if (replace_dir_name)
				memset(next_rel_path, 0, sizeof(next_rel_path));
			else
				snprintf(next_rel_path, sizeof(next_rel_path),
					 "%s%s/", rel_path, basename(src_path));
			ret = file_fill_recursive(file_list, dst_is_remote, sftp,
						  next_src_path, next_rel_path,
						  dst_path, dst_should_dir, false);
			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

int file_fill(sftp_session sftp, struct list_head *file_list, char **src_array, int cnt,
	      char *dst)
{
	bool dst_is_remote, dst_is_dir, dst_dir_no_exist, dst_should_dir, dst_must_dir;
	char *dst_path, *src_path;
	int n, ret;

	dst_path = file_find_path(dst);
	dst_path = *dst_path == '\0' ? "." : dst_path;
	dst_is_remote = file_find_hostname(dst) ? true : false;
	dst_must_dir = cnt > 1 ? true : false;

	if (file_is_directory(dst_path, dst_is_remote ? sftp : NULL, false) > 0)
		dst_is_dir = true;
	else
		dst_is_dir = false;
	dst_dir_no_exist = !dst_is_dir;

	for (n = 0; n < cnt; n++) {
		src_path = file_find_path(src_array[n]);

		if (file_is_directory(src_path, dst_is_remote ? NULL : sftp, false) > 0)
			dst_should_dir = true;
		else
			dst_should_dir = false;

		ret = file_fill_recursive(file_list, dst_is_remote, sftp,
					  src_path, "", dst_path,
					  dst_should_dir | dst_must_dir | dst_is_dir,
					  dst_dir_no_exist);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/* based on
 * https://stackoverflow.com/questions/2336242/recursive-mkdir-system-call-on-unix */
static int file_dst_prepare(struct file *f, sftp_session sftp)
{
	/* XXX: should reflect the permission of the original directory? */
	mode_t mode =  S_IRWXU | S_IRWXG | S_IRWXO;
	char path[PATH_MAX];
	char *p;
	int ret;

	strncpy(path, f->dst_path, sizeof(path));

	pr_debug("prepare for %s\n", path);

	/* mkdir -p */
	for (p = strchr(path + 1, '/'); p; p = strchr(p + 1, '/')) {
		*p = '\0';

		ret = file_directory_exists(path, sftp);
		pr_debug("check %s ret=%d\n", path, ret);
		if (ret < -1)
			return -1;
		if (ret == 1)
			goto next;

		pr_debug("mkdir %s\n", path);

		if (sftp) {
			ret = sftp_mkdir(sftp, path, mode);
			if (ret < 0 &&
			    sftp_get_error(sftp) != SSH_FX_FILE_ALREADY_EXISTS) {
				pr_err("failed to create %s: %s\n",
				       path, sftp_get_ssh_error(sftp));
				return -1;
			}
		} else {
			if (mkdir(path, mode) == -1 && errno != EEXIST) {
				pr_err("failed to create %s: %s\n",
				       path, strerrno());
				return -1;
			}
		}
	next:
		*p = '/';
	}

	/* open file with O_TRUNC to set file size 0 */
	mode = O_WRONLY|O_CREAT|O_TRUNC;
	if (sftp) {
		sftp_file sf;
		if ((sf = sftp_open(sftp, f->dst_path, mode, S_IRUSR|S_IWUSR)) == NULL) {
			pr_err("sftp_open: %s\n", sftp_get_ssh_error(sftp));
			return -1;
		}
		if (sftp_close(sf) < 0) {
			pr_err("sftp_close: %s\n", sftp_get_ssh_error(sftp));
			return -1;
		}
	} else {
		int fd;
		if ((fd = open(f->dst_path, mode, S_IRUSR|S_IWUSR)) < 0) {
			pr_err("open: %s\n", strerrno());
			return -1;
		}
		if (close(fd) < 0) {
			pr_err("close: %s\n", strerrno());
			return -1;
		}
	}

	return 0;
}


#ifdef DEBUG
void file_dump(struct list_head *file_list)
{
	struct file *f;

	list_for_each_entry(f, file_list, list) {
		pr_debug("%s %s -> %s %s %lu-byte\n",
			 f->src_path, strloc(f->src_is_remote),
			 f->dst_path, strloc(f->dst_is_remote),
			 f->size);
	}
}
#endif


static void *chunk_alloc(struct file *f)
{
	struct chunk *c;

	c = malloc(sizeof(*c));
	if (!c) {
		pr_err("%s\n", strerrno());
		return NULL;
	}
	memset(c, 0, sizeof(*c));

	c->f = f;
	c->off = 0;
	c->len = 0;
	refcnt_inc(&f->refcnt);
	return c;
}

static int get_page_mask(void)
{
	int n;
	long page_sz = sysconf(_SC_PAGESIZE);
	size_t page_mask = 0;

	for (n = 0; page_sz > 0; page_sz >>= 1, n++) {
		page_mask <<= 1;
		page_mask |= 1;
	}

	return page_mask >> 1;
}

int chunk_fill(struct list_head *file_list, struct list_head *chunk_list,
	       int nr_conn, int min_chunk_sz, int max_chunk_sz)
{
	struct chunk *c;
	struct file *f;
	size_t page_mask;
	size_t chunk_sz;
	size_t size;

	page_mask = get_page_mask();

	list_for_each_entry(f, file_list, list) {
		if (f->size <= min_chunk_sz)
			chunk_sz = f->size;
		else if (max_chunk_sz)
			chunk_sz = max_chunk_sz;
		else {
			chunk_sz = (f->size - (f->size % nr_conn)) / nr_conn;
			chunk_sz &= ~page_mask; /* align in page_sz */
			if (chunk_sz <= min_chunk_sz)
				chunk_sz = min_chunk_sz;
		}

		pr_debug("%s chunk_sz %lu-byte\n", f->src_path, chunk_sz);

		/* for (size = f->size; size > 0;) does not create a
		 * file (chunk) when file size is 0. This do {} while
		 * (size > 0) creates just open/close a 0-byte file.
		 */
		size = f->size;
		do {
			c = chunk_alloc(f);
			if (!c)
				return -1;
			c->off = f->size - size;
			c->len = size < chunk_sz ? size : chunk_sz;
			size -= c->len;
			list_add_tail(&c->list, chunk_list);
			pprint4("chunk %s 0x%010lx-0x%010lx %luB\n",
				c->f->src_path, c->off, c->off + c->len, c->len);
		} while (size > 0);
	}

	return 0;
}

#ifdef DEBUG
void chunk_dump(struct list_head *chunk_list)
{
	struct chunk *c;

	list_for_each_entry(c, chunk_list, list) {
		pr_debug("%s %s 0x%010lx-0x%010lx %lu-byte\n",
			 c->f->src_path, strloc(c->f->src_is_remote),
			 c->off, c->off + c->len, c->len);
	}
}
#endif


struct chunk *chunk_acquire(struct list_head *chunk_list)
{
	/* under the lock for chunk_list */

	struct list_head *first = chunk_list->next;
	struct chunk *c = NULL;

	if (list_empty(chunk_list))
		return NULL; /* list is empty */

	c = list_entry(first, struct chunk, list);
	list_del(first);
	return c;
}

int chunk_prepare(struct chunk *c, sftp_session sftp)
{
	struct file *f = c->f;
	int ret = 0;

	lock_acquire(&f->lock); /* XXX: is always acquiring lock per-chunk heavy? */
	if (f->state == FILE_STATE_INIT) {
		if (file_dst_prepare(f, f->dst_is_remote ? sftp : NULL) < 0) {
			ret = -1;
			goto out;
		}
		f->state = FILE_STATE_OPENED;
		pprint2("copy start: %s\n", f->src_path);
	}

out:
	lock_release(&f->lock);
	return ret;
}

static mode_t file_get_mode(const char *path, sftp_session sftp)
{
	mode_t mode;

	if (sftp) {
		sftp_attributes attr = sftp_stat(sftp, path);
		if (!attr) {
			pr_err("sftp_stat %s: %s\n", path, sftp_get_ssh_error(sftp));
			return -1;
		}
		mode = attr->permissions;
		sftp_attributes_free(attr);
	} else {
		struct stat statbuf;
		if (stat(path, &statbuf) < 0) {
			pr_err("stat %s: %s\n", path, strerrno());
			return -1;
		}
		mode = statbuf.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO);
	}
	return mode;
}

static int file_set_mode(const char *path, mode_t mode, sftp_session sftp)
{
	if (sftp) {
		if (sftp_chmod(sftp, path, mode) < 0) {
			pr_err("sftp_chmod %s: %s\n", path, sftp_get_ssh_error(sftp));
			return -1;
		}
	} else {
		if (chmod(path, mode) < 0) {
			pr_err("chmod %s: %s\n", path, strerrno());
			return -1;
		}
	}

	return 0;
}

static int chunk_open_local(const char *path, int flags, mode_t mode, size_t off)
{
	int fd;

	fd = open(path, flags, mode);
	if (fd < 0) {
		pr_err("open failed for %s: %s\n", path, strerrno());
		return -1;
	}
	if (lseek(fd, off, SEEK_SET) < 0) {
		pr_err("seek error for %s: %s\n", path, strerrno());
		close(fd);
		return -1;
	}

	return fd;
}

static sftp_file chunk_open_remote(const char *path, int flags, mode_t mode, size_t off,
				   sftp_session sftp)
{
	sftp_file sf;

	sf = sftp_open(sftp, path, flags, mode);

	if (!sf) {
		pr_err("sftp_open %s: %s\n", path, sftp_get_ssh_error(sftp));
		return NULL;
	}

	if (sftp_seek64(sf, off) < 0) {
		pr_err("sftp_seek64 %s: %s\n", path, sftp_get_ssh_error(sftp));
		return NULL;
	}

	return sf;
}

/*
 * TODO: handle case when read returns 0 (EOF).
 */
static int _chunk_copy_local_to_remote(struct chunk *c, int fd, sftp_file sf,
				       size_t sftp_buf_sz, size_t io_buf_sz,
				       size_t *counter)
{
	ssize_t read_bytes, write_bytes, remaind;
	char buf[io_buf_sz];

	for (remaind = c->len; remaind > 0;) {

		read_bytes = read(fd, buf, min(remaind, io_buf_sz));
		if (read_bytes < 0) {
			pr_err("read: %s\n", strerrno());
			return -1;
		}

		write_bytes = sftp_write2(sf, buf, read_bytes, sftp_buf_sz);
		if (write_bytes < 0) {
			pr_err("sftp_write: %d\n", sftp_get_error(sf->sftp));
			return -1;
		}

		if (write_bytes < read_bytes) {
			pr_err("failed to write full bytes to %s\n", c->f->dst_path);
			return -1;
		}

		*counter += write_bytes;
		remaind -= write_bytes;
	}

	return 0;
}

#define XFER_BUF_SIZE	16384

#ifdef ASYNC_WRITE
static int _chunk_copy_local_to_remote_async(struct chunk *c, int fd,
					     sftp_file sf, int nr_ahead, size_t *counter)
{
	ssize_t read_bytes, remaind, thrown;
	char buf[XFER_BUF_SIZE];
	int idx, ret;
	struct {
		uint32_t id;
		ssize_t  len;
	} reqs[nr_ahead];

	if (c->len == 0)
		return 0;

	remaind = thrown = c->len;
	for (idx = 0; idx < nr_ahead && thrown > 0; idx++) {
		reqs[idx].len = min(thrown, sizeof(buf));
		read_bytes = read(fd, buf, reqs[idx].len);
		if (read_bytes < 0) {
			pr_err("read: %s\n", strerrno());
			return -1;
		}
		ret = sftp_async_write(sf, buf, reqs[idx].len, &reqs[idx].id);
		if (ret < 0) {
			pr_err("sftp_async_write: %d\n", sftp_get_error(sf->sftp));
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

		reqs[idx].len = min(thrown, sizeof(buf));
		read_bytes = read(fd, buf, reqs[idx].len);
		if (read_bytes < 0) {
			pr_err("read: %s\n", strerrno());
			return -1;
		}

		ret = sftp_async_write(sf, buf, reqs[idx].len, &reqs[idx].id);
		if (ret < 0) {
			pr_err("sftp_async_write: %d\n", sftp_get_error(sf->sftp));
			return -1;
		}
		thrown -= reqs[idx].len;
	}

	if (remaind < 0) {
		pr_err("invalid remaind bytes %ld. last async_write_end bytes %lu. "
		       "last read bytes %ld\n",
		       remaind, reqs[idx].len, read_bytes);
		return -1;
	}

	return 0;
}
#endif

static int _chunk_copy_remote_to_local(struct chunk *c, int fd, sftp_file sf,
				       int nr_ahead, size_t *counter)
{
	ssize_t read_bytes, write_bytes, remaind, thrown;
	char buf[XFER_BUF_SIZE];
	int idx;
	struct {
		int id;
		ssize_t len;
	} reqs[nr_ahead];

	/* TODO: sftp_buf_sz has no effect on remote to local copy. we
	 * always use 16384 byte buffer pointed by
	 * https://api.libssh.org/stable/libssh_tutor_sftp.html. The
	 * larget read length from sftp_async_read is 65536 byte.
	 * Read sizes larget than 65536 cause a situation where data
	 * remainds but sftp_async_read returns 0.
	 */

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

static int chunk_copy_local_to_remote(struct chunk *c, sftp_session sftp,
				      size_t sftp_buf_sz, size_t io_buf_sz,
				      int nr_ahead, size_t *counter)
{
	struct file *f = c->f;
	sftp_file sf = NULL;
	mode_t mode;
	int ret = 0;
	int fd = 0;
	int flags;

	flags = O_RDONLY;
	mode = S_IRUSR;
	if ((fd = chunk_open_local(f->src_path, flags, mode, c->off)) < 0) {
		ret = -1;
		goto out;
	}

	flags = O_WRONLY;
	mode = S_IRUSR|S_IWUSR;
	if (!(sf = chunk_open_remote(f->dst_path, flags, mode, c->off, sftp))) {
		ret = -1;
		goto out;
	}

#ifndef ASYNC_WRITE
	ret = _chunk_copy_local_to_remote(c, fd, sf, sftp_buf_sz, io_buf_sz,
					  counter);
#else
	ret = _chunk_copy_local_to_remote_async(c, fd, sf, nr_ahead, counter);
#endif
	if (ret < 0)
		goto out;
out:
	if (fd > 0)
		close(fd);
	if (sf)
		sftp_close(sf);
	return ret;
}

static int chunk_copy_remote_to_local(struct chunk *c, sftp_session sftp,
				      int nr_ahead, size_t *counter)
{
	struct file *f = c->f;
	sftp_file sf = NULL;
	mode_t mode;
	int flags;
	int fd = 0;
	int ret = 0;

	flags = O_WRONLY;
	mode = S_IRUSR|S_IWUSR;
	if ((fd = chunk_open_local(f->dst_path, flags, mode, c->off)) < 0) {
		ret = -1;
		goto out;
	}

	flags = O_RDONLY;
	mode = S_IRUSR;
	if (!(sf = chunk_open_remote(f->src_path, flags, mode, c->off, sftp))) {
		ret = -1;
		goto out;
	}

	ret = _chunk_copy_remote_to_local(c, fd, sf, nr_ahead, counter);
	if (ret< 0)
		goto out;

out:
	if (fd > 0)
		close(fd);
	if (sf)
		sftp_close(sf);

	return ret;
}

static int file_cleanup(struct file *f, sftp_session sftp)
{
	sftp_session s, d;
	mode_t mode;

	if (f->dst_is_remote) {
		s = NULL;
		d = sftp;
	} else {
		s = sftp;
		d = NULL;
	}

	if ((mode = file_get_mode(f->src_path, s)) < 0)
		return -1;
	if (file_set_mode(f->dst_path, mode, d) < 0)
		return -1;
	return 0;
}

int chunk_copy(struct chunk *c, sftp_session sftp, size_t sftp_buf_sz, size_t io_buf_sz,
	       int nr_ahead, size_t *counter)
{
	struct file *f = c->f;
	int ret = 0;

	pr_debug("copy %s %s -> %s %s off=0x%010lx\n",
		 f->src_path, strloc(f->src_is_remote),
		 f->dst_path, strloc(f->dst_is_remote), c->off);

	pprint4("copy start: chunk %s 0x%010lx-0x%010lx %luB\n",
		c->f->src_path, c->off, c->off + c->len, c->len);


	if (f->dst_is_remote)
		ret = chunk_copy_local_to_remote(c, sftp, sftp_buf_sz, io_buf_sz,
						 nr_ahead, counter);
	else
		ret = chunk_copy_remote_to_local(c, sftp, nr_ahead, counter);

	if (ret < 0)
		return ret;

	pr_debug("done %s %s -> %s %s off=0x%010lx\n",
		 f->src_path, strloc(f->src_is_remote),
		 f->dst_path, strloc(f->dst_is_remote), c->off);

	pprint4("copy done: chunk %s 0x%010lx-0x%010lx %luB\n",
		c->f->src_path, c->off, c->off + c->len, c->len);

	if (refcnt_dec(&f->refcnt) == 0) {
		sftp_session s, d;
		mode_t mode;

		f->state = FILE_STATE_DONE;
		pprint2("copy done: %s\n", f->src_path);

		ret = file_cleanup(f, sftp);
	}


	return ret;
}
