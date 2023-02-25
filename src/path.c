#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <libgen.h>

#include <ssh.h>
#include <util.h>
#include <list.h>
#include <atomic.h>
#include <path.h>



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

int walk_src_path(sftp_session sftp, const char *src_path, struct list_head *path_list)
{
	return walk_path_recursive(sftp, src_path, path_list);
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

int resolve_dst_path(sftp_session sftp, const char *src_path, const char *dst_path,
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

int prepare_chunk(struct list_head *path_list, struct list_head *chunk_list,
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
