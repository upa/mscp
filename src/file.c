#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>

#include <ssh.h>
#include <util.h>
#include <file.h>
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
int file_is_directory(char *path, sftp_session sftp)
{
        int ret = 0;

        if (sftp) {
                char *remote_path = file_find_path(path);
                sftp_attributes attr;

                char *p = *remote_path == '\0' ? "." : remote_path;
                attr = sftp_stat(sftp, p);
                if (!attr) {
                        pr_err("%s: %s\n", p,
                               ssh_get_error(sftp_ssh(sftp)));
                        ret = -1;
                } else if (attr->type == SSH_FILEXFER_TYPE_DIRECTORY)
                        ret = 1;
                sftp_attributes_free(attr);
        } else {
                struct stat statbuf;
                if (stat(path, &statbuf) < 0) {
                        pr_err("%s: %s\n", path, strerrno());
                        ret = -1;
                } else if ((statbuf.st_mode & S_IFMT) == S_IFDIR)
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
                                pr_err("%s: %s\n", path, ssh_get_error(sftp_ssh(sftp)));
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

static struct file *file_alloc(char *path, size_t size, bool remote)
{
        struct file *f;

        f = malloc(sizeof(*f));
        if (!f) {
                pr_err("%s\n", strerrno());
                return NULL;
        }
        memset(f, 0, sizeof(*f));

        strncpy(f->path, path, PATH_MAX);
        f->size = size;
        f->remote = remote;
        lock_init(&f->lock);

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

int file_fill(sftp_session sftp, struct list_head *file_list, char **src_array, int cnt)
{
        char *src, *path;
        int ret, n;

        for (n = 0; n < cnt; n++) {
                src = *(src_array + n);
                path = file_find_path(src);
                path = *path == '\0' ? "." : path;
                if (file_has_hostname(src))
                        ret = file_fill_remote_recursive(path, sftp, file_list);
                else
                        ret = file_fill_local_recursive(path, file_list);
                if (ret < 0)
                        return -1;
        }

        return 0;
}

int file_fill_dst(char *target, struct list_head *file_list)
{
        bool dst_remote = file_find_hostname(target) ? true : false;
        char *dst_path = file_find_path(target);
        struct file *f;

        dst_path = *dst_path == '\0' ? "." : dst_path;

        list_for_each_entry(f, file_list, list) {
                f->dst_remote = dst_remote;
                strncat(f->dst_path, dst_path, PATH_MAX);
                strncat(f->dst_path, "/", PATH_MAX);
                strncat(f->dst_path, f->path, PATH_MAX);
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
                                       path, ssh_get_error(sftp_ssh(sftp)));
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

        return 0;
}


#ifdef DEBUG
void file_dump(struct list_head *file_list)
{
        struct file *f;

        list_for_each_entry(f, file_list, list) {
                pr_debug("%s %s -> %s %s %lu-byte\n",
                         f->path, f->remote ? "(remote)" : "(local)",
                         f->dst_path, f->dst_remote ? "(remote)" : "(local)",
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

                pr_debug("%s chunk_sz %lu-byte\n", f->path, chunk_sz);

                for (size = f->size; size > 0;) {
                        c = chunk_alloc(f);
                        if (!c)
                                return -1;
                        c->off = f->size - size;
                        c->len = size < chunk_sz ? size : chunk_sz;
                        size -= c->len;
                        list_add_tail(&c->list, chunk_list);
                }
        }

        return 0;
}

#ifdef DEBUG
void chunk_dump(struct list_head *chunk_list)
{
        struct chunk *c;

        list_for_each_entry(c, chunk_list, list) {
                pr_debug("%s %s 0x%010lx-0x%010lx %lu-byte\n",
                         c->f->path, c->f->remote ? "(remote)" : "(local)",
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
                if (file_dst_prepare(f, f->dst_remote ? sftp : NULL) < 0) {
                        ret = -1;
                        goto out;
                }
                f->state = FILE_STATE_OPENED;
        }

out:
        lock_release(&f->lock);
        return ret;
}

static mode_t chunk_get_mode(const char *path, sftp_session sftp)
{
        mode_t mode;

        if (sftp) {
                sftp_attributes attr = sftp_stat(sftp, path);
                if (!attr) {
                        pr_err("failed to get stat for %s: %s\n",
                               path, ssh_get_error(sftp_ssh(sftp)));
                        return -1;
                }
                mode = attr->permissions;
                sftp_attributes_free(attr);
        } else {
                struct stat statbuf;
                if (stat(path, &statbuf) < 0) {
                        pr_err("failed to get stat for %s: %s\n",
                               path, strerrno());
                        return -1;
                }
                mode = statbuf.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO);
        }
        return mode;
}

static int chunk_set_mode(const char *path, mode_t mode, sftp_session sftp)
{
        if (sftp) {
                if (sftp_chmod(sftp, path, mode) < 0) {
                        pr_err("failed to chmod %s: %s\n",
                               path, ssh_get_error(sftp_ssh(sftp)));
                        return -1;
                }
        } else {
                if (chmod(path, mode) < 0) {
                        pr_err("failed to chmod %s: %s\n",
                               path, strerrno());
                        return -1;
                }
        }

        return 0;
}

static int chunk_open_local(const char *path, int flags, size_t off)
{
        int fd;

        fd = open(path, flags);
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

static sftp_file chunk_open_remote(const char *path, int flags, size_t off,
                                   sftp_session sftp)
{
        sftp_file sf;

        sf = sftp_open(sftp, path, flags, S_IRWXU); /* chmdo after copy finished */

        if (!sf) {
                pr_err("open failed for remote %s: %s\n",
                       path, ssh_get_error(sftp_ssh(sftp)));
                return NULL;
        }

        if (sftp_seek64(sf, off) < 0) {
                pr_err("seek error for %s: %s\n", path, ssh_get_error(sftp_ssh(sftp)));
                return NULL;
        }

        return sf;
}

static int chunk_copy_local_to_remote(struct chunk *c, sftp_session sftp, size_t buf_sz,
                                      size_t *counter)
{
        struct file *f = c->f;
        char buf[buf_sz];
        size_t remaind, remaind2, read_size;
        sftp_file sf = NULL;
        mode_t mode;
        int fd = 0;
        int ret, ret2;

        if ((fd = chunk_open_local(f->path, O_RDONLY, c->off)) < 0) {
                ret = -1;
                goto out;
        }

        if (!(sf = chunk_open_remote(f->dst_path, O_WRONLY | O_CREAT, c->off, sftp))) {
                ret = -1;
                goto out;
        }

        for (remaind = c->len; remaind > 0;) {
                read_size = buf_sz < remaind ? buf_sz : remaind;
                ret = read(fd, buf, read_size);
                if (ret < 0) {
                        pr_err("failed to read %s: %s\n", f->path, strerrno());
                        ret = -1;
                        goto out;
                }
                if (ret == 0)
                        break;

                for (remaind2 = ret; remaind2 > 0;) {
                        ret2 = sftp_write(sf, buf + (ret - remaind2), remaind2);
                        if (ret2 < 0) {
                                pr_err("failed to write to %s: %s\n", f->dst_path,
                                       ssh_get_error(sftp_ssh(sftp)));
                                ret = -1;
                                goto out;
                        }
                        c->done += ret2;
                        *counter += ret2;
                        remaind2 -= ret2;
                }

                remaind -= ret;
        }

        if ((mode = chunk_get_mode(f->path, NULL)) < 0) {
                ret = -1;
                goto out;
        }
        if (chunk_set_mode(f->dst_path, mode, sftp) < 0) {
                ret = -1;
        }

out:
        if (fd > 0)
                close(fd);
        if (sf)
                sftp_close(sf);
        return ret;
}

static int chunk_copy_remote_to_local(struct chunk *c, sftp_session sftp, size_t buf_sz,
                                      size_t *counter)
{
        struct file *f = c->f;
        char buf[buf_sz];
        size_t remaind, remaind2, read_size;
        sftp_file sf = NULL;
        mode_t mode;
        int fd = 0;
        int ret, ret2;

        if ((fd = chunk_open_local(f->dst_path, O_WRONLY | O_CREAT, c->off)) < 0) {
                ret = -1;
                goto out;
        }

        if (!(sf = chunk_open_remote(f->path, O_RDONLY, c->off, sftp))) {
                ret = -1;
                goto out;
        }

        for (remaind = c->len; remaind > 0;) {
                read_size = buf_sz < remaind ? buf_sz : remaind;
                ret = sftp_read(sf, buf, read_size);
                if (ret < 0) {
                        pr_err("failed to read from %s: %s\n", f->dst_path,
                               ssh_get_error(sftp_ssh(sftp)));
                        ret = -1;
                        goto out;
                }

                for (remaind2 = ret; remaind2 > 0;) {
                        ret2 = write(fd, buf + (ret - remaind2), remaind2);
                        if (ret2 < 0) {
                                pr_err("failed to write to %s: %s\n", f->dst_path,
                                       strerrno());
                                ret = -1;
                                goto out;
                        }
                        c->done += ret2;
                        *counter += ret2;
                        remaind2 -= ret2;
                }

                remaind -= ret;
        }

        if ((mode = chunk_get_mode(f->path, sftp)) < 0) {
                ret = -1;
                goto out;
        }
        if (chunk_set_mode(f->dst_path, mode, NULL) < 0) {
                ret = -1;
        }

out:
        if (fd > 0)
                close(fd);
        if (sf)
                sftp_close(sf);

        return ret;
}

int chunk_copy(struct chunk *c, sftp_session sftp, size_t buf_sz, size_t *counter)
{
        struct file *f = c->f;
        int ret;

        pr_debug("copy %s %s -> %s %s off=0x%010lx\n",
                 f->path, f->remote ? "(remote)" : "(local)",
                 f->dst_path, f->dst_remote ? "(remote)" : "(local)", c->off);

        if (f->dst_remote)
                ret = chunk_copy_local_to_remote(c, sftp, buf_sz, counter);
        else
                ret = chunk_copy_remote_to_local(c, sftp, buf_sz, counter);

        if (ret < 0)
                return ret;

        if (refcnt_dec(&f->refcnt) == 0)
                f->state = FILE_STATE_DONE;

        return ret;
}
