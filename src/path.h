#ifndef _PATH_H_
#define _PATH_H_

#include <limits.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#include <list.h>
#include <atomic.h>
#include <ssh.h>
#include <message.h>

struct path {
	struct list_head	list;	/* mscp->path_list */

	char	path[PATH_MAX];		/* file path */
	size_t	size;			/* size of file on this path */
	mode_t	mode;			/* permission */

	char	dst_path[PATH_MAX];	/* copy dst path */

	int	state;
	lock	lock;
	refcnt	refcnt;
};
#define FILE_STATE_INIT         0
#define FILE_STATE_OPENED       1
#define FILE_STATE_DONE         2

struct chunk {
	struct list_head	list;	/* mscp->chunk_list */

	struct path *p;
	size_t	off;	/* offset of this chunk on the file on path p */
	size_t	len;	/* length of this chunk */
	size_t	done;	/* copied bytes for this chunk by a thread */
};



/* recursivly walk through src_path and fill path_list for each file */
int walk_src_path(sftp_session src_sftp, const char *src_path,
		  struct list_head *path_list);

/* fill path->dst_path for all files */
int resolve_dst_path(int msg_fd, const char *src_path, const char *dst_path,
		     struct list_head *path_list,
		     bool src_path_is_dir, bool dst_path_is_dir,
		     bool dst_path_should_dir);

/* resolve chunks from files in the path_list */
int resolve_chunk(struct list_head *path_list, struct list_head *chunk_list,
		  int nr_conn, int min_chunk_sz, int max_chunk_sz);

/* copy a chunk. either src_sftp or dst_sftp is not null, and another is null */
int copy_chunk(int msg_fd, struct chunk *c, sftp_session src_sftp, sftp_session dst_sftp,
	       int nr_ahead, int buf_sz, size_t *counter);

/* just print contents. just for debugging */
void path_dump(struct list_head *path_list);
void chunk_dump(struct list_head *chunk_list);




/* wrap DIR/dirent and sftp_dir/sftp_attribute. not thread safe */
struct mscp_dir {
        DIR *l;
        sftp_dir r;
        sftp_session sftp;
};
typedef struct mscp_dir mdir;

struct mscp_dirent {
        struct dirent *l;
        sftp_attributes r;
};
typedef struct mscp_dirent mdirent;

#define mdirent_name(e) ((e->l) ? e->l->d_name : e->r->name)
#define mdirent_is_dir(e) ((e->l) ?                                     \
                           (e->l->d_type == DT_DIR) :                   \
                           (e->r->type == SSH_FILEXFER_TYPE_DIRECTORY))
#define mdirent_is_null(e) (e->l == NULL && e->r == NULL)

static mdir *mscp_opendir(const char *path, sftp_session sftp)
{
        mdir *d;

        if (!(d = malloc(sizeof(*d))))
                return NULL;
        memset(d, 0, sizeof(*d));

        d->sftp = sftp;

        if (sftp) {
                d->r = sftp_opendir(sftp, path);
                if (!d->r) {
                        mscp_set_error("sftp_opendir '%s': %s",
				       path, sftp_get_ssh_error(sftp));
                        free(d);
                        return NULL;
                }
        } else {
                d->l = opendir(path);
                if (!d->l) {
                        mscp_set_error("opendir '%s': %s", path, strerrno());
                        free(d);
                        return NULL;
                }
        }
        return d;
}

static int mscp_closedir(mdir *d)
{
        int ret;
        if (d->r)
                ret = sftp_closedir(d->r);
        else
                ret = closedir(d->l);
        free(d);
        return ret;
}

static mdirent *mscp_readdir(mdir *d)
{
        static mdirent e;

        memset(&e, 0, sizeof(e));
        if (d->r)
                e.r = sftp_readdir(d->sftp, d->r);
        else
                e.l = readdir(d->l);
        return &e;
}

/* wrap retriving error */
static const char *mscp_strerror(sftp_session sftp)
{
	if (sftp)
		return sftp_get_ssh_error(sftp);
	return strerrno();
}

/* warp stat/sftp_stat */
struct mscp_stat {
        struct stat l;
        sftp_attributes r;
};
typedef struct mscp_stat mstat;

static int mscp_stat(const char *path, mstat *s, sftp_session sftp)
{
        memset(s, 0, sizeof(*s));

        if (sftp) {
                s->r = sftp_stat(sftp, path);
                if (!s->r)
                        return -1;
        } else {
                if (stat(path, &s->l) < 0)
                        return -1;
        }

        return 0;
}

static int mscp_stat_check_err_noent(sftp_session sftp)
{
	if (sftp) {
		if (sftp_get_error(sftp) == SSH_FX_NO_SUCH_PATH ||
		    sftp_get_error(sftp) == SSH_FX_NO_SUCH_FILE)
			return 0;
	} else {
		if (errno == ENOENT)
			return 0;
	}
	return -1;
}

static void mscp_stat_free(mstat s) {
        if (s.r)
                sftp_attributes_free(s.r);
}

#define mstat_size(s) ((s.r) ? s.r->size : s.l.st_size)
#define mstat_mode(s) ((s.r) ?                                  \
                       s.r->permissions :                       \
                       s.l.st_mode & (S_IRWXU|S_IRWXG|S_IRWXO))
#define mstat_is_regular(s) ((s.r) ?                                    \
                             (s.r->type == SSH_FILEXFER_TYPE_REGULAR) : \
                             S_ISREG(s.l.st_mode))
#define mstat_is_dir(s) ((s.r) ?                        \
                         (s.r->type == SSH_FILEXFER_TYPE_DIRECTORY) :   \
                         S_ISDIR(s.l.st_mode))

/* wrap mkdir */
static int mscp_mkdir(const char *path, mode_t mode, sftp_session sftp)
{
	int ret;

	if (sftp) {
		ret = sftp_mkdir(sftp, path, mode);
		if (ret < 0 &&
		    sftp_get_error(sftp) != SSH_FX_FILE_ALREADY_EXISTS) {
			mscp_set_error("sftp_mkdir '%s': %s",
				       path, sftp_get_ssh_error(sftp));
			return -1;
		}
	} else {
		if (mkdir(path, mode) == -1 && errno != EEXIST) {
			mscp_set_error("mkdir '%s': %s", path, strerrno());
			return -1;
		}
	}

	return 0;
}

/* wrap open/sftp_open */
struct mscp_file_handle {
	int fd;
	sftp_file sf;
};
typedef struct mscp_file_handle mfh;

static mfh mscp_open(const char *path, int flags, mode_t mode, size_t off,
		      sftp_session sftp)
{
	mfh h;

	h.fd = -1;
	h.sf = NULL;

	if (sftp) {
		h.sf = sftp_open(sftp, path, flags, mode);
		if (!h.sf) {
			mscp_set_error("sftp_open '%s': %s",
				       path, sftp_get_ssh_error(sftp));
			return h;
		}

		if (sftp_seek64(h.sf, off) < 0) {
			mscp_set_error("sftp_seek64 '%s': %s",
				       path, sftp_get_ssh_error(sftp));
			sftp_close(h.sf);
			h.sf = NULL;
			return h;
		}
	} else {
		h.fd = open(path, flags, mode);
		if (h.fd < 0) {
			mscp_set_error("open '%s': %s", path, strerrno());
			return h;
		}
		if (lseek(h.fd, off, SEEK_SET) < 0) {
			mscp_set_error("lseek '%s': %s", path, strerrno());
			close(h.fd);
			h.fd = -1;
			return h;
		}
	}

	return h;
}

#define mscp_open_is_failed(h) (h.fd < 0 && h.sf == NULL)

static void mscp_close(mfh h)
{
	if (h.sf)
		sftp_close(h.sf);
	if (h.fd > 0)
		close(h.fd);
	h.sf = NULL;
	h.fd = -1;
}

/* wrap chmod/sftp_chmod */

static int mscp_chmod(const char *path, mode_t mode, sftp_session sftp)
{
	if (sftp) {
		if (sftp_chmod(sftp, path, mode) < 0)  {
			mscp_set_error("sftp_chmod '%s': %s",
				       path, sftp_get_ssh_error(sftp));
			return -1;
		}
	} else {
		if (chmod(path, mode) < 0) {
			mscp_set_error("chmod '%s': %s", path, strerrno());
			return -1;
		}
	}

	return 0;
}

#endif /* _PATH_H_ */
