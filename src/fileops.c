/* SPDX-License-Identifier: GPL-3.0-only */
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/times.h>
#include <utime.h>

#include <fileops.h>
#include <ssh.h>
#include <print.h>
#include <platform.h>

sftp_session __thread tls_sftp;
/* tls_sftp is used *_wrapped() functions */

void set_tls_sftp_session(sftp_session sftp)
{
	tls_sftp = sftp;
}

static void sftp_err_to_errno(sftp_session sftp)
{
	int sftperr = sftp_get_error(sftp);

	switch (sftperr) {
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
		pr_warn("unkown SSH_FX response %d", sftperr);
	}
}

MDIR *mscp_opendir(const char *path, sftp_session sftp)
{
	MDIR *md;

	if (!(md = malloc(sizeof(*md))))
		return NULL;
	memset(md, 0, sizeof(*md));

	if (sftp) {
		md->remote = sftp_opendir(sftp, path);
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

void mscp_closedir(MDIR *md)
{
	int ret;
	if (md->remote)
		sftp_closedir(md->remote);
	else
		closedir(md->local);

	free(md);
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
		strncpy(tls_dirent.d_name, attr->name, sizeof(tls_dirent.d_name) - 1);
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
	st->st_size = attr->size;
	st->st_uid = attr->uid;
	st->st_gid = attr->gid;
	st->st_mode = attr->permissions;

#if defined(__APPLE__)
#define st_atim st_atimespec
#define st_mtim st_mtimespec
#define st_ctim st_ctimespec
#endif
	st->st_atim.tv_sec = attr->atime;
	st->st_atim.tv_nsec = attr->atime_nseconds;
	st->st_mtim.tv_sec = attr->mtime;
	st->st_mtim.tv_nsec = attr->mtime_nseconds;
	st->st_ctim.tv_sec = attr->createtime;
	st->st_ctim.tv_nsec = attr->createtime_nseconds;

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
		pr_warn("unkown SSH_FILEXFER_TYPE %d", attr->type);
	}
}

int mscp_stat(const char *path, struct stat *st, sftp_session sftp)
{
	sftp_attributes attr;
	int ret = 0;

	memset(st, 0, sizeof(*st));

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

off_t mscp_lseek(mf *f, off_t off)
{
	off_t ret;

	if (f->remote) {
		ret = sftp_seek64(f->remote, off);
		sftp_err_to_errno(f->remote->sftp);
	} else
		ret = lseek(f->local, off, SEEK_SET);

	return ret;
}

int mscp_setstat(const char *path, struct stat *st, bool preserve_ts, sftp_session sftp)
{
	int ret;

	if (sftp) {
		struct sftp_attributes_struct attr;
		memset(&attr, 0, sizeof(attr));
		attr.permissions = st->st_mode;
		attr.size = st->st_size;
		attr.flags = (SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_SIZE);
		if (preserve_ts) {
			attr.atime = st->st_atim.tv_sec;
			attr.atime_nseconds = st->st_atim.tv_nsec;
			attr.mtime = st->st_mtim.tv_sec;
			attr.mtime_nseconds = st->st_mtim.tv_nsec;
			attr.flags |= (SSH_FILEXFER_ATTR_ACCESSTIME |
				       SSH_FILEXFER_ATTR_MODIFYTIME |
				       SSH_FILEXFER_ATTR_SUBSECOND_TIMES);
		}
		ret = sftp_setstat(sftp, path, &attr);
		sftp_err_to_errno(sftp);
	} else {
		if ((ret = truncate(path, st->st_size)) < 0)
			return ret;
		if (preserve_ts) {
			if ((ret = setutimes(path, st->st_atim, st->st_mtim)) < 0)
				return ret;
		}
		if ((ret = chmod(path, st->st_mode)) < 0)
			return ret;
	}

	return ret;
}

int mscp_glob(const char *pattern, int flags, glob_t *pglob, sftp_session sftp)
{
	int ret;
	if (sftp) {
#ifndef GLOB_ALTDIRFUNC
#define GLOB_NOALTDIRMAGIC INT_MAX
		/* musl does not implement GLOB_ALTDIRFUNC */
		pglob->gl_pathc = 1;
		pglob->gl_pathv = malloc(sizeof(char *));
		pglob->gl_pathv[0] = strdup(pattern);
		pglob->gl_offs = GLOB_NOALTDIRMAGIC;
		return 0;
#else
		flags |= GLOB_ALTDIRFUNC;
		set_tls_sftp_session(sftp);
#if defined(__APPLE__) || defined(__FreeBSD__)
		pglob->gl_opendir = (void *(*)(const char *))mscp_opendir_wrapped;
		pglob->gl_readdir = (struct dirent * (*)(void *)) mscp_readdir;
		pglob->gl_closedir = (void (*)(void *))mscp_closedir;
		pglob->gl_lstat = mscp_lstat_wrapped;
		pglob->gl_stat = mscp_stat_wrapped;
#elif linux
		pglob->gl_opendir = (void *(*)(const char *))mscp_opendir_wrapped;
		pglob->gl_readdir = (void *(*)(void *))mscp_readdir;
		pglob->gl_closedir = (void (*)(void *))mscp_closedir;
		pglob->gl_lstat = (int (*)(const char *, void *))mscp_lstat_wrapped;
		pglob->gl_stat = (int (*)(const char *, void *))mscp_stat_wrapped;
#else
#error unsupported platform
#endif
#endif
	}

	ret = glob(pattern, flags, NULL, pglob);

	if (sftp)
		set_tls_sftp_session(NULL);
	return ret;
}

void mscp_globfree(glob_t *pglob)
{
#ifndef GLOB_ALTDIRFUNC
	if (pglob->gl_offs == GLOB_NOALTDIRMAGIC) {
		free(pglob->gl_pathv[0]);
		free(pglob->gl_pathv);
		return;
	}
#endif
	globfree(pglob);
}
