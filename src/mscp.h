#ifndef _MSCP_H_
#define _MSCP_H_

#include <stdbool.h>
#include <limits.h>

#define MSCP_DIRECTION_L2R	1
#define MSCP_DIRECTION_R2L	2

#define MSCP_MAX_COREMASK_STR	64

struct mscp_opts {
	/* mscp options */
	int	direction;	/* MSCP_DIRECTION_ */

	int	nr_threads;
	int	nr_ahead;
	size_t	min_chunk_sz;
	size_t	max_chunk_sz;
	size_t	buf_sz;
	char	coremask[MSCP_MAX_COREMASK_STR];

	/* messaging */
	int	severity; 	/* messaging severity. set MSCP_SERVERITY_* */
	int	msg_fd;		/* fd to output message. default STDOUT,
				 * and -1 disables output */

	bool	dryrun;
};

#define MSCP_SSH_MAX_LOGIN_NAME		64
#define MSCP_SSH_MAX_PORT_STR		32
#define MSCP_SSH_MAX_IDENTITY_PATH	PATH_MAX
#define MSCP_SSH_MAX_CIPHER_STR		32
#define MSCP_SSH_MAX_HMAC_STR		32
#define MSCP_SSH_MAX_COMP_STR		32 /* yes, no, zlib, zlib@openssh.com, none */
#define MSCP_SSH_MAX_PASSWORD		128
#define MSCP_SSH_MAX_PASSPHRASE		128

struct mscp_ssh_opts {
	/* ssh options */
	char	login_name[MSCP_SSH_MAX_LOGIN_NAME];
	char	port[MSCP_SSH_MAX_PORT_STR];
	char	identity[MSCP_SSH_MAX_IDENTITY_PATH];
	char	cipher[MSCP_SSH_MAX_CIPHER_STR];
	char	hmac[MSCP_SSH_MAX_HMAC_STR];
	char	compress[MSCP_SSH_MAX_COMP_STR];

	char	password[MSCP_SSH_MAX_PASSWORD];
	char	passphrase[MSCP_SSH_MAX_PASSPHRASE];

	int	debug_level;
	bool	no_hostkey_check;
	bool	enable_nagle;
};

struct mscp_stats {
	size_t total;	/* total bytes to be transferred */
	size_t done;	/* total bytes transferred */
};

struct mscp;

/* initialize and return a mscp instance with option validation  */
struct mscp *mscp_init(const char *remote_host,
		       struct mscp_opts *o, struct mscp_ssh_opts *s);

/* establish the first SFTP session. mscp_prepare() and mscp_start()
 * requires mscp_connect() beforehand */
int mscp_connect(struct mscp *m);

/* add a source file path to be copied */
int mscp_add_src_path(struct mscp *m, const char *src_path);

/* set the destination file path */
int mscp_set_dst_path(struct mscp *m, const char *dst_path);

/* check source files, resolve destination file paths for all source
 * files, and prepare chunks for all files. */
int mscp_prepare(struct mscp *m);

/* start to copy files */
int mscp_start(struct mscp *m);

/* stop copying files */
void mscp_stop(struct mscp *m);

/* get stats */
void mscp_get_stats(struct mscp *m, struct mscp_stats *s);

/* cleanup mscp instance. after mscp_cleanup(), process can restart
 * from mscp_connect() with the same setting. */
void mscp_cleanup(struct mscp *m);

/* free mscp instance */
void mscp_free(struct mscp *m);


/* messaging with mscp */

/* severity filter for messages. specifiy it with mscp_opts->serverity.
 */
enum {
	MSCP_SEVERITY_NONE	= -1,
	MSCP_SEVERITY_ERR	= 0,
	MSCP_SEVERITY_WARN	= 1,
	MSCP_SEVERITY_NOTICE	= 2,
        MSCP_SEVERITY_INFO	= 3,
	MSCP_SEVERITY_DEBUG	= 4,
};

/* set fd to which mscp writes messages. default is STDOUT.
 * supposed fd is pipe write fd.
 */
void mscp_set_msg_fd(struct mscp *m, int fd);

/* retrieve the fd for read message from mscp */
int mscp_get_msg_fd(struct mscp *m);

/* get message for the most recent error (not thread safe) */
const char *mscp_get_error();




#endif /* _MSCP_H_ */
