#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>

#include <ssh.h>
#include <util.h>
#include <file.h>

bool file_has_hostname(char *path)
{
        char *p;

        p = strchr(path, ':');
        if (p) {
                if (p == path || ((p > path) && *(p - 1) == '\\')) {
                        /* first byte is colon or escaped colon, skip */
                        return false;
                } else {
                        return true;
                }
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
int file_is_directory(char *path, sftp_session sftp)
{
        int ret = 0;

        if (sftp) {
                char *remote_path = file_find_path(path);
                sftp_attributes attr;

                char *p = *remote_path == '\0' ? "." : remote_path;
                attr = sftp_stat(sftp, p);
                if (!attr) {
                        pr_err("file %s: %s\n", p,
                               ssh_get_error(sftp_ssh(sftp)));
                        ret = -1;
                } else if (attr->type == SSH_FILEXFER_TYPE_DIRECTORY)
                        ret = 1;
                sftp_attributes_free(attr);
        } else {
                struct stat statbuf;
                if (stat(path, &statbuf) < 0) {
                        pr_err("file %s: %s\n", path, strerrno());
                        ret = -1;
                } else if ((statbuf.st_mode & S_IFMT) == S_IFDIR)
                        ret = 1;
        }

        return ret;
}

static struct file *file_alloc(char *path, size_t size, bool remote)
{
        struct file *f;

        f = malloc(sizeof(*f));
        if (!f) {
                pr_err("%s\n", strerrno());
                return NULL;
        }
        memset(f, 0, sizeof(*f));

        f->path = strdup(path);
        if (!f->path) {
                pr_err("%s\n", strerrno());
                free(f);
                return NULL;
        }

        f->size = size;
        f->remote = remote;

        return f;
}

static bool file_should_skip(char *path)
{
        int len = strlen(path);
        if ((len == 1 && strncmp(path, ".", 1) == 0) ||
            (len == 2 && strncmp(path, "..", 2) == 0)) {
                return true;
        }
        return false;
}


static int file_fill_local_recursive(char *path, struct list_head *head)
{
        char child[PATH_MAX];
        struct stat statbuf;
        struct dirent *de;
        DIR *dir;
        int ret;

        ret = file_is_directory(path, NULL);
        if (ret < 0)
                return -1;

        if (ret == 1) {
                if ((dir = opendir(path)) == NULL) {
                        pr_err("opend to open dir %s: %s\n", path, strerrno());
                        return -1;
                }

                while ((de = readdir(dir)) != NULL) {
                        if (file_should_skip(de->d_name))
                                continue;
                        snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
                        ret = file_fill_local_recursive(child, head);
                        if (ret < 0)
                                return ret;
                }
        } else {
                /* path is file */
                if (stat(path, &statbuf) < 0) {
                        pr_err("file %s: %s\n", path, strerrno());
                        return -1;
                }

                if ((statbuf.st_mode & S_IFMT) == S_IFREG ||
                    (statbuf.st_mode & S_IFMT) == S_IFLNK) {
                        struct file *f = file_alloc(path, statbuf.st_size, false);
                        if (!f) {
                                pr_err("%s\n", strerrno());
                                return -1;
                        }
                        list_add_tail(&f->list, head);
                }
        }

        return 0;
}

static int file_fill_remote_recursive(char *path, sftp_session sftp,
                                      struct list_head *head)
{
        char child[PATH_MAX];
        sftp_attributes attr;
        sftp_dir dir;
        int ret;

        ret = file_is_directory(path, sftp);
        if (ret < 0)
                return -1;

        if (ret == 1) {
                dir = sftp_opendir(sftp, path);
                if (!dir) {
                        pr_err("failed to open dir %s: %s\n", path,
                               ssh_get_error(sftp_ssh(sftp)));
                        return -1;
                }

                while ((attr = sftp_readdir(sftp, dir)) != NULL) {
                        if (file_should_skip(attr->name))
                                continue;

                        snprintf(child, sizeof(child), "%s/%s", path, attr->name);
                        ret = file_fill_remote_recursive(child, sftp, head);
                        if (ret < 0)
                                return ret;
                        sftp_attributes_free(attr);
                }

                if (!sftp_dir_eof(dir)) {
                        pr_err("can't list directory %s: %s\n", path,
                               ssh_get_error(sftp_ssh(sftp)));
                        return -1;
                }

                if (sftp_closedir(dir) != SSH_OK) {
                        pr_err("can't close directory %s: %s\n", path,
                               ssh_get_error(sftp_ssh(sftp)));
                        return -1;
                }

        } else {
                /* path is file */
                attr = sftp_stat(sftp, path);
                if (!attr) {
                        pr_err("failed to get stat for %s: %s\n",
                               path, ssh_get_error(sftp_ssh(sftp)));
                        return -1;
                }

                /* skip special and unknown files */
                if (attr->type == SSH_FILEXFER_TYPE_REGULAR ||
                    attr->type == SSH_FILEXFER_TYPE_SYMLINK) {
                        struct file *f = file_alloc(path, attr->size, true);
                        if (!f) {
                                pr_err("%s\n", strerrno());
                                return -1;
                        }
                        list_add(&f->list, head);
                        sftp_attributes_free(attr);
                }
        }

        return 0;
}

int file_fill(sftp_session sftp, struct list_head *head, char **src_array, int count)
{
        char *src, *path;
        int ret, n;

        for (n = 0; n < count; n++) {
                src = *(src_array + n);
                path = file_find_path(src);
                path = *path == '\0' ? "." : path;
                if (file_has_hostname(src))
                        ret = file_fill_remote_recursive(path, sftp, head);
                else
                        ret = file_fill_local_recursive(path, head);
                if (ret < 0)
                        return -1;
        }

        return 0;
}


#ifdef DEBUG
void file_dump(struct list_head *file_head)
{
        struct file *f;

        list_for_each_entry(f, file_head, list) {
                pr_debug("%s %s %lu-byte\n", f->path,
                         f->remote ? "(remote)" : "(local)", f->size);
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

int chunk_fill(struct list_head *file_head, struct list_head *chunk_head,
               int nr_conn, int min_chunk_sz, int max_chunk_sz)
{
        struct chunk *c;
        struct file *f;
        size_t page_mask;
        size_t chunk_sz;
        size_t size;

        page_mask = get_page_mask();

        list_for_each_entry(f, file_head, list) {
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

                pr_debug("%s chunk_sz %lu-byte\n", f->path, chunk_sz);

                for (size = f->size; size > 0;) {
                        c = chunk_alloc(f);
                        if (!c)
                                return -1;
                        c->off = f->size - size;
                        c->len = size < chunk_sz ? size : chunk_sz;
                        size -= c->len;
                        list_add_tail(&c->list, chunk_head);
                }
        }

        return 0;
}

#ifdef DEBUG
void chunk_dump(struct list_head *chunk_head)
{
        struct chunk *c;

        list_for_each_entry(c, chunk_head, list) {
                pr_debug("%s %s 0x%010lx-0x%010lx %lu-byte\n",
                         c->f->path, c->f->remote ? "(remote)" : "(local)",
                         c->off, c->off + c->len, c->len);
        }
}
#endif
