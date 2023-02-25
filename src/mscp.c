#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <math.h>
#include <pthread.h>

#include <list.h>       
#include <util.h>       
#include <ssh.h>                
#include <path.h>
#include <pprint.h>             
#include <atomic.h>             
#include <platform.h>
#include <mscp.h>

struct mscp {
	const char		*remote;	/* remote host (and uername) */
	struct mscp_opts	*opts;
	struct ssh_opts		ssh_opts;

	sftp_session		first;		/* first sftp session */

	char 			dst_path[PATH_MAX];
	struct list_head	src_list;
	struct list_head	path_list;
	struct list_head	chunk_list;
	lock			chunk_lock;

	struct mscp_thread	*threads;
};

struct src {
	struct list_head list;
	char *path;
};

#define DEFAULT_MIN_CHUNK_SZ    (64 << 20)      /* 64MB */
#define DEFAULT_NR_AHEAD        32
#define DEFAULT_BUF_SZ          16384

struct mscp *mscp_init(const char *remote_host, struct mscp_opts *opts)
{
	struct mscp *m;

	m = malloc(sizeof(*m));
	if (!m) {
		pr_err("failed to allocate memory: %s\n", strerrno());
		return NULL;
	}

	memset(m, 0, sizeof(*m));
	INIT_LIST_HEAD(&m->src_list);
	INIT_LIST_HEAD(&m->path_list);
	INIT_LIST_HEAD(&m->chunk_list);
	lock_init(&m->chunk_lock);
	m->remote = strdup(remote_host);
	if (!m->remote) {
		pr_err("failed to allocate memory: %s\n", strerrno());
		free(m);
		return NULL;
	}

	m->opts = opts;
	m->ssh_opts.login_name		= opts->ssh_login_name;
	m->ssh_opts.port		= opts->ssh_port;
	m->ssh_opts.identity		= opts->ssh_identity;
	m->ssh_opts.cipher		= opts->ssh_cipher_spec;
	m->ssh_opts.hmac		= opts->ssh_hmac_spec;
	m->ssh_opts.compress		= opts->ssh_compress_level;
	m->ssh_opts.debuglevel		= opts->ssh_debug_level;
	m->ssh_opts.no_hostkey_check	= opts->ssh_no_hostkey_check;
	m->ssh_opts.nodelay		= opts->ssh_disable_tcp_nodely;

	m->first = ssh_init_sftp_session(m->remote, &m->ssh_opts);
	if (!m->first) {
		free(m);
		return NULL;
	}

	return m;
}

int mscp_add_src_path(struct mscp *m, const char *src_path)
{
	struct src *s;

	s = malloc(sizeof(*s));
	if (!s) {
		pr_err("failed to allocate memory: %s\n", strerrno());
		return -1;
	}

	memset(s, 0, sizeof(*s));
	s->path = strdup(src_path);
	if (!s->path) {
		pr_err("failed to allocate memory: %s\n", strerrno());
		free(s);
		return -1;
	}

	list_add_tail(&s->list, &m->src_list);
	return 0;
}

static void mscp_free_src_list(struct mscp *m)
{
	struct src *s, *n;

	list_for_each_entry_safe(s, n, &m->src_list, list) {
		free(s->path);
		list_del(&s->list);
		free(s);
	}
}

int mscp_set_dst_path(struct mscp *m, const char *dst_path)
{
	if (strlen(dst_path) + 1 >= PATH_MAX) {
		pr_err("too long dst path: %s\n", dst_path);
		return -1;
	}

	strncpy(m->dst_path, dst_path, PATH_MAX);
	return 0;
}

int mscp_prepare(struct mscp *m)
{
	sftp_session src_sftp = NULL, dst_sftp = NULL;
	bool src_path_is_dir, dst_path_is_dir;
	struct list_head tmp;
	struct src *s;
	mstat ss, ds;
	
	switch (m->opts->direct) {
	case MSCP_DIRECT_L2R:
		src_sftp = NULL;
		dst_sftp = m->first;
		break;
	case MSCP_DIRECT_R2L:
		src_sftp = m->first;
		dst_sftp = NULL;
		break;
	default:
		pr_err("invalid mscp direction: %d\n", m->opts->direct);
		return -1;
	}

	if (mscp_stat(m->dst_path, &ds, dst_sftp) == 0) {
		if (mstat_is_dir(ds))
			dst_path_is_dir = true;
		mscp_stat_free(ds);
	} else
		dst_path_is_dir = false;

	/* walk a src_path recusively, and resolve path->dst_path for each src */
	list_for_each_entry(s, &m->src_list, list) {
		if (mscp_stat(s->path, &ss, src_sftp) < 0) {
			pr_err("stat: %s\n", mscp_strerror(src_sftp));
			return -1;
		}
		src_path_is_dir = mstat_is_dir(ss);
		mscp_stat_free(ss);

		INIT_LIST_HEAD(&tmp);
		if (walk_src_path(src_sftp, s->path, &tmp) < 0)
			return -1;
		
		if (resolve_dst_path(s->path, m->dst_path, &tmp,
				     src_path_is_dir, dst_path_is_dir) < 0)
			return -1;

		list_splice_tail(&tmp, m->path_list.prev);
	}

	if (resolve_chunk(&m->path_list, &m->chunk_list, m->opts->nr_threads,
			  m->opts->max_chunk_sz, m->opts->min_chunk_sz) < 0)
		return -1;

	mscp_free_src_list(m);

	return 0;
}

int mscp_start(struct mscp *m)
{
	return 0;
}
