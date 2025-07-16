/* SPDX-License-Identifier: GPL-3.0-only */
#include <stdbool.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>

#include <pool.h>
#include <minmax.h>
#include <ssh.h>
#include <path.h>
#include <checkpoint.h>
#include <fileops.h>
#include <atomic.h>
#include <platform.h>
#include <print.h>
#include <strerrno.h>
#include <mscp.h>
#include <bwlimit.h>

#include <openbsd-compat/openbsd-compat.h>

struct mscp_thread {
	struct mscp *m;
	sftp_session sftp;

	/* attributes used by copy threads */
	size_t copied_bytes;
	int id;
	int cpu;

	/* thread-specific values */
	pthread_t tid;
	int ret;
};

struct mscp {
	char *remote; /* remote host (and uername) */
	int direction; /* copy direction */
	char dst_path[PATH_MAX];

	struct mscp_opts *opts;
	struct mscp_ssh_opts *ssh_opts;

	int *cores; /* usable cpu cores by COREMASK */
	int nr_cores; /* length of array of cores */

	sem_t *sem; /* semaphore for concurrent  connecting ssh sessions */

	sftp_session first; /* first sftp session */

	pool *src_pool, *path_pool, *chunk_pool, *thread_pool;

	size_t total_bytes; /* total_bytes to be copied */
	bool chunk_pool_ready;
#define chunk_pool_is_ready(m) ((m)->chunk_pool_ready)
#define chunk_pool_set_ready(m, b) ((m)->chunk_pool_ready = b)

	struct bwlimit bw; /* bandwidth limit mechanism */

	struct mscp_thread scan; /* mscp_thread for mscp_scan_thread() */
};

#define DEFAULT_MIN_CHUNK_SZ (16 << 20) /* 16MB */
#define DEFAULT_NR_AHEAD 32
#define DEFAULT_BUF_SZ 16384
/* XXX: we use 16384 byte buffer pointed by
 * https://api.libssh.org/stable/libssh_tutor_sftp.html. The larget
 * read length from sftp_async_read is 65536 byte. Read sizes larger
 * than 65536 cause a situation where data remainds but
 * sftp_async_read returns 0.
 */

#define DEFAULT_MAX_STARTUPS 8

#define non_null_string(s) (s[0] != '\0')

static int expand_coremask(const char *coremask, int **cores, int *nr_cores)
{
	int n, *core_list, core_list_len = 0, nr_usable, nr_all;
	char c[2] = { 'x', '\0' };
	const char *_coremask;
	long v, needle;
	int ncores = nr_cpus();

	/*
         * This function returns array of usable cores in `cores` and
         * returns the number of usable cores (array length) through
         * nr_cores.
         */

	if (strncmp(coremask, "0x", 2) == 0)
		_coremask = coremask + 2;
	else
		_coremask = coremask;

	core_list = realloc(NULL, sizeof(int) * 64);
	if (!core_list) {
		priv_set_errv("realloc: %s", strerrno());
		return -1;
	}

	nr_usable = 0;
	nr_all = 0;
	for (n = strlen(_coremask) - 1; n >= 0; n--) {
		c[0] = _coremask[n];
		v = strtol(c, NULL, 16);
		if (v == LONG_MIN || v == LONG_MAX) {
			priv_set_errv("invalid coremask: %s", coremask);
			return -1;
		}

		for (needle = 0x01; needle < 0x10; needle <<= 1) {
			nr_all++;
			if (nr_all > ncores)
				break; /* too long coremask */
			if (v & needle) {
				nr_usable++;
				core_list = realloc(core_list, sizeof(int) * nr_usable);
				if (!core_list) {
					priv_set_errv("realloc: %s", strerrno());
					return -1;
				}
				core_list[nr_usable - 1] = nr_all - 1;
			}
		}
	}

	if (nr_usable < 1) {
		priv_set_errv("invalid core mask: %s", coremask);
		return -1;
	}

	*cores = core_list;
	*nr_cores = nr_usable;
	return 0;
}

static int default_nr_threads()
{
	return (int)(floor(log(nr_cpus()) * 2) + 1);
}

static int validate_and_set_defaut_params(struct mscp_opts *o)
{
	if (o->nr_threads < 0) {
		priv_set_errv("invalid nr_threads: %d", o->nr_threads);
		return -1;
	} else if (o->nr_threads == 0)
		o->nr_threads = default_nr_threads();

	if (o->nr_ahead < 0) {
		priv_set_errv("invalid nr_ahead: %d", o->nr_ahead);
		return -1;
	} else if (o->nr_ahead == 0)
		o->nr_ahead = DEFAULT_NR_AHEAD;

	if (o->min_chunk_sz == 0)
		o->min_chunk_sz = DEFAULT_MIN_CHUNK_SZ;

	if (o->max_chunk_sz) {
		if (o->min_chunk_sz > o->max_chunk_sz) {
			priv_set_errv("smaller max chunk size than "
				      "min chunk size: %lu < %lu",
				      o->max_chunk_sz, o->min_chunk_sz);
			return -1;
		}
	}

	if (o->buf_sz == 0)
		o->buf_sz = DEFAULT_BUF_SZ;
	else if (o->buf_sz == 0) {
		priv_set_errv("invalid buf size: %lu", o->buf_sz);
		return -1;
	}

	if (o->max_startups == 0)
		o->max_startups = DEFAULT_MAX_STARTUPS;
	else if (o->max_startups < 0) {
		priv_set_errv("invalid max_startups: %d", o->max_startups);
		return -1;
	}

	if (o->interval > 0) {
		/* when the interval is set, establish SSH connections sequentially. */
		o->max_startups = 1;
	}

	return 0;
}

int mscp_set_remote(struct mscp *m, const char *remote_host, int direction)
{
	if (!remote_host) {
		priv_set_errv("empty remote host");
		return -1;
	}

	if (!(direction == MSCP_DIRECTION_L2R || direction == MSCP_DIRECTION_R2L)) {
		priv_set_errv("invalid copy direction: %d", direction);
		return -1;
	}

	if (!(m->remote = strdup(remote_host))) {
		priv_set_errv("strdup: %s", strerrno());
		return -1;
	}
	m->direction = direction;

	return 0;
}

struct mscp *mscp_init(struct mscp_opts *o, struct mscp_ssh_opts *s)
{
	struct mscp *m;
	int n;

	set_print_severity(o->severity);

	if (validate_and_set_defaut_params(o) < 0) {
		return NULL;
	}

	if (!(m = malloc(sizeof(*m)))) {
		priv_set_errv("malloc: %s", strerrno());
		return NULL;
	}
	memset(m, 0, sizeof(*m));
	m->opts = o;
	m->ssh_opts = s;
	chunk_pool_set_ready(m, false);

	if (!(m->src_pool = pool_new())) {
		priv_set_errv("pool_new: %s", strerrno());
		goto free_out;
	}

	if (!(m->path_pool = pool_new())) {
		priv_set_errv("pool_new: %s", strerrno());
		goto free_out;
	}

	if (!(m->chunk_pool = pool_new())) {
		priv_set_errv("pool_new: %s", strerrno());
		goto free_out;
	}

	if (!(m->thread_pool = pool_new())) {
		priv_set_errv("pool_new: %s", strerrno());
		goto free_out;
	}

	if ((m->sem = sem_create(o->max_startups)) == NULL) {
		priv_set_errv("sem_create: %s", strerrno());
		goto free_out;
	}

	if (o->coremask) {
		if (expand_coremask(o->coremask, &m->cores, &m->nr_cores) < 0)
			goto free_out;
		char b[512], c[8];
		memset(b, 0, sizeof(b));
		for (n = 0; n < m->nr_cores; n++) {
			memset(c, 0, sizeof(c));
			snprintf(c, sizeof(c) - 1, " %d", m->cores[n]);
			strlcat(b, c, sizeof(b));
		}
		pr_notice("usable cpu cores:%s", b);
	}

	if (bwlimit_init(&m->bw, o->bitrate, 100) < 0) { /* 100ms window (hardcoded) */
		priv_set_errv("bwlimit_init: %s", strerrno());
		goto free_out;
	}
	pr_notice("bitrate limit: %lu bps", o->bitrate);

	return m;

free_out:
	if (m->src_pool)
		pool_free(m->src_pool);
	if (m->path_pool)
		pool_free(m->path_pool);
	if (m->chunk_pool)
		pool_free(m->chunk_pool);
	if (m->thread_pool)
		pool_free(m->thread_pool);
	if (m->remote)
		free(m->remote);
	free(m);
	return NULL;
}

int mscp_connect(struct mscp *m)
{
	m->first = ssh_init_sftp_session(m->remote, m->ssh_opts);
	if (!m->first)
		return -1;

	return 0;
}

int mscp_add_src_path(struct mscp *m, const char *src_path)
{
	char *s = strdup(src_path);
	if (!s) {
		priv_set_errv("strdup: %s", strerrno());
		return -1;
	}
	if (pool_push(m->src_pool, s) < 0) {
		priv_set_errv("pool_push: %s", strerrno());
		return -1;
	}
	return 0;
}

int mscp_set_dst_path(struct mscp *m, const char *dst_path)
{
	if (strlen(dst_path) + 1 >= PATH_MAX) {
		priv_set_errv("too long dst path: %s", dst_path);
		return -1;
	}

	if (!non_null_string(dst_path))
		strncpy(m->dst_path, ".", 1);
	else
		strncpy(m->dst_path, dst_path, PATH_MAX);

	return 0;
}

static size_t get_page_mask(void)
{
	size_t page_sz = sysconf(_SC_PAGESIZE);
	return ~(page_sz - 1);
}

static void mscp_stop_copy_thread(struct mscp *m)
{
	struct mscp_thread *t;
	unsigned int idx;
	pool_lock(m->thread_pool);
	pool_for_each(m->thread_pool, t, idx) {
		if (t->tid)
			pthread_cancel(t->tid);
	}
	pool_unlock(m->thread_pool);
}

static void mscp_stop_scan_thread(struct mscp *m)
{
	if (m->scan.tid)
		pthread_cancel(m->scan.tid);
}

void mscp_stop(struct mscp *m)
{
	mscp_stop_scan_thread(m);
	mscp_stop_copy_thread(m);
}

void *mscp_scan_thread(void *arg)
{
	struct mscp_thread *t = arg;
	struct mscp *m = t->m;
	sftp_session src_sftp = NULL, dst_sftp = NULL;
	struct path_resolve_args a;
	struct path *p;
	struct stat ss, ds;
	char *src_path;
	glob_t pglob;
	int n;

	switch (m->direction) {
	case MSCP_DIRECTION_L2R:
		src_sftp = NULL;
		dst_sftp = t->sftp;
		break;
	case MSCP_DIRECTION_R2L:
		src_sftp = t->sftp;
		dst_sftp = NULL;
		break;
	default:
		pr_err("invalid copy direction: %d", m->direction);
		goto err_out;
	}

	/* initialize path_resolve_args */
	memset(&a, 0, sizeof(a));
	a.total_bytes = &m->total_bytes;

	if (pool_size(m->src_pool) > 1)
		a.dst_path_should_dir = true;

	if (mscp_stat(m->dst_path, &ds, dst_sftp) == 0) {
		if (S_ISDIR(ds.st_mode))
			a.dst_path_is_dir = true;
	}

	a.path_pool = m->path_pool;
	a.chunk_pool = m->chunk_pool;
	a.nr_conn = m->opts->nr_threads;
	a.min_chunk_sz = m->opts->min_chunk_sz;
	a.max_chunk_sz = m->opts->max_chunk_sz;
	a.chunk_align = get_page_mask();

	pr_info("start to walk source path(s)");

	/* walk each src_path recusively, and resolve path->dst_path for each src */
	pool_iter_for_each(m->src_pool, src_path) {
		memset(&pglob, 0, sizeof(pglob));
		if (mscp_glob(src_path, GLOB_NOCHECK, &pglob, src_sftp) < 0) {
			pr_err("mscp_glob: %s", strerrno());
			goto err_out;
		}

		for (n = 0; n < pglob.gl_pathc; n++) {
			if (mscp_stat(pglob.gl_pathv[n], &ss, src_sftp) < 0) {
				pr_err("stat: %s %s", src_path, strerrno());
				goto err_out;
			}

			if (!a.dst_path_should_dir && pglob.gl_pathc > 1)
				a.dst_path_should_dir = true; /* we have over 1 srces */

			/* set path specific args */
			a.src_path = pglob.gl_pathv[n];
			a.dst_path = m->dst_path;
			a.src_path_is_dir = S_ISDIR(ss.st_mode);

			if (walk_src_path(src_sftp, pglob.gl_pathv[n], &a) < 0)
				goto err_out;
		}
		mscp_globfree(&pglob);
	}

	pr_info("walk source path(s) done");
	t->ret = 0;
	chunk_pool_set_ready(m, true);
	return NULL;

err_out:
	t->ret = -1;
	chunk_pool_set_ready(m, true);
	return NULL;
}

int mscp_scan(struct mscp *m)
{
	struct mscp_thread *t = &m->scan;
	int ret;

	memset(t, 0, sizeof(*t));
	t->m = m;
	t->sftp = m->first;

	if ((ret = pthread_create(&t->tid, NULL, mscp_scan_thread, t)) < 0) {
		priv_set_err("pthread_create: %d", ret);
		return -1;
	}

	/* We wait for there are over nr_threads chunks to determine
	 * actual number of threads (and connections), or scan
	 * finished. If the number of chunks are smaller than
	 * nr_threads, we adjust nr_threads to the number of chunks.
	 */
	while (!chunk_pool_is_ready(m) && pool_size(m->chunk_pool) < m->opts->nr_threads)
		usleep(100);

	return 0;
}

int mscp_scan_join(struct mscp *m)
{
	struct mscp_thread *t = &m->scan;
	if (t->tid) {
		pthread_join(t->tid, NULL);
		t->tid = 0;
		return t->ret;
	}
	return 0;
}

int mscp_checkpoint_get_remote(const char *pathname, char *remote, size_t len, int *dir)
{
	return checkpoint_load_remote(pathname, remote, len, dir);
}

int mscp_checkpoint_load(struct mscp *m, const char *pathname)
{
	struct chunk *c;
	unsigned int i;

	if (checkpoint_load_paths(pathname, m->path_pool, m->chunk_pool) < 0)
		return -1;

	/* totaling up bytes to be transferred and set chunk_pool is
	 * ready instead of the mscp_scan thread */
	m->total_bytes = 0;
	pool_for_each(m->chunk_pool, c, i) {
		m->total_bytes += c->len;
	}
	chunk_pool_set_ready(m, true);

	return 0;
}

int mscp_checkpoint_save(struct mscp *m, const char *pathname)
{
	return checkpoint_save(pathname, m->direction, m->ssh_opts->login_name, m->remote,
			       m->path_pool, m->chunk_pool);
}

static void *mscp_copy_thread(void *arg);

static struct mscp_thread *mscp_copy_thread_spawn(struct mscp *m, int id)
{
	struct mscp_thread *t;
	int ret;

	if (!(t = malloc(sizeof(*t)))) {
		priv_set_errv("malloc: %s", strerrno());
		return NULL;
	}

	memset(t, 0, sizeof(*t));
	t->m = m;
	t->id = id;
	if (m->cores == NULL)
		t->cpu = -1; /* not pinned to cpu */
	else
		t->cpu = m->cores[id % m->nr_cores];

	if ((ret = pthread_create(&t->tid, NULL, mscp_copy_thread, t)) < 0) {
		priv_set_errv("pthread_create: %d", ret);
		free(t);
		return NULL;
	}

	return t;
}

int mscp_start(struct mscp *m)
{
	struct mscp_thread *t;
	int n, ret = 0;

	if ((n = pool_size(m->chunk_pool)) < m->opts->nr_threads) {
		pr_notice("we have %d chunk(s), set number of connections to %d", n, n);
		m->opts->nr_threads = n;
	}

	for (n = 0; n < m->opts->nr_threads; n++) {
		t = mscp_copy_thread_spawn(m, n);
		if (!t)
			break;
		if (pool_push_lock(m->thread_pool, t) < 0) {
			priv_set_errv("pool_push_lock: %s", strerrno());
			break;
		}
	}

	return n;
}

int mscp_join(struct mscp *m)
{
	struct mscp_thread *t;
	struct path *p;
	unsigned int idx;
	size_t total_copied_bytes = 0, nr_copied = 0, nr_tobe_copied = 0;
	int n, ret = 0;

	/* waiting for scan thread joins... */
	ret = mscp_scan_join(m);

	/* waiting for copy threads join... */
	pool_for_each(m->thread_pool, t, idx) {
		pthread_join(t->tid, NULL);
	}

	pool_for_each(m->thread_pool, t, idx) {
		total_copied_bytes += t->copied_bytes;
		if (t->ret != 0)
			ret = t->ret;
		if (t->sftp) {
			ssh_sftp_close(t->sftp);
			t->sftp = NULL;
		}
	}

	/* count up number of transferred files */
	pool_iter_for_each(m->path_pool, p) {
		nr_tobe_copied++;
		if (p->state == FILE_STATE_DONE) {
			nr_copied++;
		}
	}

	if (m->first) {
		ssh_sftp_close(m->first);
		m->first = NULL;
	}

	pr_notice("%lu/%lu bytes copied for %lu/%lu files", total_copied_bytes,
		  m->total_bytes, nr_copied, nr_tobe_copied);

	return ret;
}

/* copy thread-related functions */

static void wait_for_interval(int interval)
{
	_Atomic static long next;
	struct timeval t;
	long now;

	gettimeofday(&t, NULL);
	now = t.tv_sec * 1000000 + t.tv_usec;

	if (next - now > 0)
		usleep(next - now);

	next = now + interval * 1000000;
}

void *mscp_copy_thread(void *arg)
{
	sftp_session src_sftp, dst_sftp;
	struct mscp_thread *t = arg;
	struct mscp *m = t->m;
	struct chunk *c;
	bool next_chunk_exist;

	/* when error occurs, each thread prints error messages
	 * immediately with pr_* functions. */

	if (t->cpu > -1) {
		if (set_thread_affinity(pthread_self(), t->cpu) < 0) {
			pr_err("set_thread_affinity: %s", priv_get_err());
			goto err_out;
		}
		pr_notice("thread[%d]: pin to cpu core %d", t->id, t->cpu);
	}

	if (sem_wait(m->sem) < 0) {
		pr_err("sem_wait: %s", strerrno());
		goto err_out;
	}

	if ((next_chunk_exist = pool_iter_has_next_lock(m->chunk_pool))) {
		if (m->opts->interval > 0)
			wait_for_interval(m->opts->interval);
		pr_notice("thread[%d]: connecting to %s", t->id, m->remote);
		t->sftp = ssh_init_sftp_session(m->remote, m->ssh_opts);
	}

	if (sem_post(m->sem) < 0) {
		pr_err("sem_post: %s", strerrno());
		goto err_out;
	}

	if (!next_chunk_exist) {
		pr_notice("thread[%d]: no more connections needed", t->id);
		goto out;
	}

	if (!t->sftp) {
		pr_err("thread[%d]: %s", t->id, priv_get_err());
		goto err_out;
	}

	switch (m->direction) {
	case MSCP_DIRECTION_L2R:
		src_sftp = NULL;
		dst_sftp = t->sftp;
		break;
	case MSCP_DIRECTION_R2L:
		src_sftp = t->sftp;
		dst_sftp = NULL;
		break;
	default:
		assert(false);
		goto err_out; /* not reached */
	}

	while (1) {
		c = pool_iter_next_lock(m->chunk_pool);
		if (c == NULL) {
			if (!chunk_pool_is_ready(m)) {
				/* a new chunk will be added. wait for it. */
				usleep(100);
				continue;
			}
			break; /* no more chunks */
		}

		if ((t->ret = copy_chunk(c, src_sftp, dst_sftp, m->opts->nr_ahead,
					 m->opts->buf_sz, m->opts->preserve_ts, &m->bw,
					 &t->copied_bytes)) < 0)
			break;
	}

	if (t->ret < 0) {
		pr_err("thread[%d]: copy failed: %s -> %s, 0x%010lx-0x%010lx, %s", t->id,
		       c->p->path, c->p->dst_path, c->off, c->off + c->len,
		       priv_get_err());
	}

	return NULL;

err_out:
	t->ret = -1;
	return NULL;
out:
	t->ret = 0;
	return NULL;
}

/* cleanup-related functions */

void mscp_cleanup(struct mscp *m)
{
	if (m->first) {
		ssh_sftp_close(m->first);
		m->first = NULL;
	}

	pool_zeroize(m->src_pool, free);
	pool_zeroize(m->path_pool, (pool_map_f)free_path);
	pool_zeroize(m->chunk_pool, free);
	pool_zeroize(m->thread_pool, free);
}

void mscp_free(struct mscp *m)
{
	pool_destroy(m->src_pool, free);
	pool_destroy(m->path_pool, (pool_map_f)free_path);

	if (m->remote)
		free(m->remote);
	if (m->cores)
		free(m->cores);

	sem_release(m->sem);
	free(m);
}

void mscp_get_stats(struct mscp *m, struct mscp_stats *s)
{
	struct mscp_thread *t;
	unsigned int idx;

	s->total = m->total_bytes;
	s->done = 0;

	pool_for_each(m->thread_pool, t, idx) {
		s->done += t->copied_bytes;
	}
}
