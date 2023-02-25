#ifndef _MSCP_H_
#define _MSCP_H_

#include <stdbool.h>

#define MSCP_DIRECT_L2R	1
#define MSCP_DIRECT_R2L	2

struct mscp_opts {
	/* mscp options */
	int	direct;	/* MSCP_DIRECT_ */

	int	nr_threads;
	int	nr_ahead;
	size_t	min_chunk_sz;
	size_t	max_chunk_sz;
	size_t	buf_sz;

	int	verbose_level;
	bool	quiet;
	bool	dryrun;

	/* ssh options */
	char	ssh_login_name[64];
	char	ssh_port[32];
	char	ssh_identity[PATH_MAX];
	char	ssh_cipher_spec[64];
	char	ssh_hmac_spec[32];
	int	ssh_debug_level;
	int	ssh_compress_level;
	bool	ssh_no_hostkey_check;
	bool	ssh_disable_tcp_nodely;
};

struct mscp;

struct mscp *mscp_init(const char *remote_host, struct mscp_opts *opts);
int mscp_add_src_path(struct mscp *m, const char *src_path);
int mscp_set_dst_path(struct mscp *m, const char *dst_path);
int mscp_prepare(struct mscp *m);
int mscp_start(struct mscp *m);

#endif /* _MSCP_H_ */
