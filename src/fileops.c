#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>

#include <fileops.h>
#include <ssh.h>
#include <message.h>


sftp_session __thread tls_sftp;
/* tls_sftp is used *_wrapped() functions */

void set_tls_sftp_session(sftp_session sftp)
{
	tls_sftp = sftp;
}

static void sftp_err_to_errno(sftp_session sftp)
{
	int sftperr = sftp_get_error(sftp);

	switch (sftperr){
	case SSH_FX_OK:
	case SSH_FX_EOF:
		errno = 0;
		break;
	case SSH_FX_NO_SUCH_FILE:
	case SSH_FX_NO_SUCH_PATH:
		errno = ENOENT;
		break;
	case SSH_FX_PERMISSION_DENIED:
		errno = EACCES;
		break;
	case SSH_FX_FAILURE:
		errno = EINVAL;
	case SSH_FX_BAD_MESSAGE:
		errno = EBADMSG;
	case SSH_FX_NO_CONNECTION:
		errno = ENOTCONN;
		break;
	case SSH_FX_CONNECTION_LOST:
		errno = ENETRESET;
		break;
	case SSH_FX_OP_UNSUPPORTED:
		errno = EOPNOTSUPP;
		break;
	case SSH_FX_INVALID_HANDLE:
		errno = EBADF;
		break;
	case SSH_FX_FILE_ALREADY_EXISTS:
		errno = EEXIST;
		break;
	case SSH_FX_WRITE_PROTECT:
		errno = EPERM;
		break;
	case SSH_FX_NO_MEDIA:
		errno = ENODEV;
		break;
	default:
		mpr_warn(stderr, "unkown SSH_FX response %d", sftperr);
	}
}


MDIR *mscp_opendir(const char *path, sftp_session sftp)
{
	MDIR *md;

	if (!(md = malloc(sizeof(*md))))
		return NULL;
	memset(md, 0, sizeof(*md));

	if (tls_sftp) {
		md->remote = sftp_opendir(tls_sftp, path);
		sftp_err_to_errno(sftp);
		if (!md->remote) {
			goto free_out;
		}
	} else {
		md->local = opendir(path);
		if (!md->local) {
			goto free_out;
		}
	}

	return md;

free_out:
	free(md);
	return NULL;
}

MDIR *mscp_opendir_wrapped(const char *path)
{
	return mscp_opendir(path, tls_sftp);
}

int mscp_closedir(MDIR *md)
{
	int ret;
	if (md->remote) {
		ret = sftp_closedir(md->remote);
		if (ret < 0)
			sftp_err_to_errno(md->remote->sftp);
	} else
		ret = closedir(md->local);

	free(md);
	return ret;
}


struct dirent __thread tls_dirent;
/* tls_dirent contains dirent converted from sftp_attributes returned
 * from sftp_readdir(). This trick is derived from openssh's
 * fudge_readdir() */

struct dirent *mscp_readdir(MDIR *md)
{
	sftp_attributes attr;
	struct dirent *ret = NULL;
	static int inum = 1;

	if (md->remote) {
		attr = sftp_readdir(md->remote->sftp, md->remote);
		if (!attr) {
			sftp_err_to_errno(md->remote->sftp);
			return NULL;
		}

		memset(&tls_dirent, 0, sizeof(tls_dirent));
		strlcpy(tls_dirent.d_name, attr->name, sizeof(tls_dirent.d_name));
		tls_dirent.d_ino = inum++;
		if (!inum)
			inum = 1;
		ret = &tls_dirent;
		sftp_attributes_free(attr);
	} else
		ret = readdir(md->local);

	return ret;
}

int mscp_mkdir(const char *path, mode_t mode, sftp_session sftp)
{
	int ret;

	if (sftp) {
		ret = sftp_mkdir(sftp, path, mode);
		fprintf(stderr, "after sftp_mkdir(%s), sftp_get_error is %d\n",
			path, sftp_get_error(sftp));
		sftp_err_to_errno(sftp);
	} else
		ret = mkdir(path, mode);

	if (ret < 0 && errno == EEXIST) {
		ret = 0;
	}

	return ret;
}


static void sftp_attr_to_stat(sftp_attributes attr, struct stat *st)
{
        memset(st, 0, sizeof(*st));
	st->st_size	= attr->size;
	st->st_uid	= attr->uid;
	st->st_gid	= attr->gid;
	st->st_mode	= attr->permissions;

	switch (attr->type) {
	case SSH_FILEXFER_TYPE_REGULAR:
		st->st_mode |= S_IFREG;
		break;
	case SSH_FILEXFER_TYPE_DIRECTORY:
		st->st_mode |= S_IFDIR;
		break;
	case SSH_FILEXFER_TYPE_SYMLINK:
		st->st_mode |= S_IFLNK;
		break;
	case SSH_FILEXFER_TYPE_SPECIAL:
		st->st_mode |= S_IFCHR; /* or block? */
		break;
	case SSH_FILEXFER_TYPE_UNKNOWN:
		st->st_mode |= S_IFIFO; /* really? */
		break;
	default:
		mpr_warn(stderr, "unkown SSH_FILEXFER_TYPE %d", attr->type);
	}

	/* ToDo: convert atime, ctime, and mtime */
}


int mscp_stat(const char *path, struct stat *st, sftp_session sftp)
{
	sftp_attributes attr;
	int ret = 0;

	if (sftp) {
		attr = sftp_stat(sftp, path);
		sftp_err_to_errno(sftp);
		if (!attr)
			return -1;

		sftp_attr_to_stat(attr, st);
		sftp_attributes_free(attr);
		ret = 0;
	} else
		ret = stat(path, st);

	return ret;
}

int mscp_stat_wrapped(const char *path, struct stat *st)
{
	return mscp_stat(path, st, tls_sftp);
}

int mscp_lstat(const char *path, struct stat *st, sftp_session sftp)
{
	sftp_attributes attr;
	int ret = 0;

	if (sftp) {
		attr = sftp_lstat(sftp, path);
		sftp_err_to_errno(sftp);
		if (!attr)
			return -1;

		sftp_attr_to_stat(attr, st);
		sftp_attributes_free(attr);
		ret = 0;
	} else
		ret = lstat(path, st);

	return ret;
}

int mscp_lstat_wrapped(const char *path, struct stat *st)
{
	return mscp_lstat(path, st, tls_sftp);
}


mf *mscp_open(const char *path, int flags, mode_t mode, sftp_session sftp)
{
	mf *f;

	f = malloc(sizeof(*f));
	if (!f)
		return NULL;
	memset(f, 0, sizeof(*f));

	if (sftp) {
		f->remote = sftp_open(sftp, path, flags, mode);
		if (!f->remote) {
			sftp_err_to_errno(sftp);
			goto free_out;
		}
	} else {
		f->local = open(path, flags, mode);
		if (f->local < 0)
			goto free_out;
	}

	return f;

free_out:
	free(f);
	return NULL;
}

void mscp_close(mf *f)
{
	if (f->remote)
		sftp_close(f->remote);
	if (f->local > 0)
		close(f->local);
	free(f);
}

int mscp_lseek(mf *f, size_t off)
{
	int ret;

	if (f->remote) {
		ret = sftp_seek64(f->remote, off);
		sftp_err_to_errno(f->remote->sftp);
	} else
		ret = lseek(f->local, off, SEEK_SET);

	return ret;
}

int mscp_chmod(const char *path, mode_t mode, sftp_session sftp)
{
	int ret;

	if (sftp) {
		ret = sftp_chmod(sftp, path, mode);
		sftp_err_to_errno(sftp);
	} else
		ret = chmod(path, mode);

	return ret;
}
