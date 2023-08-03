
#include <dirent.h>
#include <sys/stat.h>

#include <ssh.h>

void set_tls_sftp_session(sftp_session sftp);
/* sftp_session set by set_tls_sftp_session is sued in
 mscp_open_wrapped(), mscp_stat_wrapped(), and
 mscp_lstat_wrapped(). This _wrapped() functions exist for
 sftp_glob() */

struct mdir_struct {
	DIR *local;
	sftp_dir remote;
};
typedef struct mdir_struct MDIR;

/* directory operations */
MDIR *mscp_opendir(const char *path, sftp_session sftp);

MDIR *mscp_opendir_wrapped(const char *path);
int mscp_closedir(MDIR *md);
struct dirent *mscp_readdir(MDIR *md);

int mscp_mkdir(const char *path, mode_t mode, sftp_session sftp);

/* stat operations */
int mscp_stat(const char *path, struct stat *st, sftp_session sftp);
int mscp_stat_wrapped(const char *path, struct stat *st);

int mscp_lstat(const char *path, struct stat *st, sftp_session sftp);
int mscp_lstat_wrapped(const char *path, struct stat *st);


/* file operations */

struct mf_struct {
	sftp_file remote;
	int local;
};
typedef struct mf_struct mf;

mf *mscp_open(const char *path, int flags, mode_t mode, sftp_session sftp);
void mscp_close(mf *f);
int mscp_lseek(mf *f, size_t off);
int mscp_chmod(const char *path, mode_t mode, sftp_session sftp);
