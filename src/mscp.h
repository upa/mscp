#ifndef _MSCP_H_
#define _MSCP_H_

#include <stdbool.h>
#include <limits.h>

#define MSCP_DIRECTION_L2R	1
#define MSCP_DIRECTION_R2L	2

#define MSCP_MAX_COREMASK_STR	64
#define MSCP_MAX_LOGIN_NAME	64
#define MSCP_MAX_PORT_STR	32
#define MSCP_MAX_IDENTITY_PATH	PATH_MAX
#define MSCP_MAX_CIPHER_STR	32
#define MSCP_MAX_HMACP_STR	32

struct mscp_opts {
	/* mscp options */
	int	direction;	/* MSCP_DIRECTION_ */

	int	nr_threads;
	int	nr_ahead;
	size_t	min_chunk_sz;
	size_t	max_chunk_sz;
	size_t	buf_sz;
	char	coremask[MSCP_MAX_COREMASK_STR];

	int	verbose_level;
	bool	quiet;
	bool	dryrun;

	/* ssh options */
	char	ssh_login_name[MSCP_MAX_LOGIN_NAME];
	char	ssh_port[MSCP_MAX_PORT_STR];
	char	ssh_identity[MSCP_MAX_IDENTITY_PATH];
	char	ssh_cipher_spec[MSCP_MAX_CIPHER_STR];
	char	ssh_hmac_spec[MSCP_MAX_HMACP_STR];
	int	ssh_debug_level;
	int	ssh_compress_level;
	bool	ssh_no_hostkey_check;
	bool	ssh_disable_tcp_nodely;
};

struct mscp;

/* initialize and return a mscp instance with option validation  */
struct mscp *mscp_init(const char *remote_host, struct mscp_opts *opts);

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

/* cleanup mscp instance. after mscp_cleanup(), process can restart
 * from mscp_connect() with the same setting. */
void mscp_cleanup(struct mscp *m);

/* free mscp instance */
void mscp_free(struct mscp *m);

#endif /* _MSCP_H_ */
