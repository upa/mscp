#include <stdbool.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/time.h>

#include <list.h>       
#include <util.h>       
#include <ssh.h>                
#include <path.h>
#include <fileops.h>
#include <atomic.h>             
#include <platform.h>
#include <message.h>
#include <mscp.h>


struct mscp {
	char			*remote;	/* remote host (and uername) */
	int			direction;	/* copy direction */
	struct mscp_opts	*opts;
	struct mscp_ssh_opts	*ssh_opts;

	FILE			*msg_fp;	/* writer fd for message pipe */

	int			*cores;		/* usable cpu cores by COREMASK */
	int			nr_cores;	/* length of array of cores */

	sem_t			*sem;		/* semaphore for concurrent 
						 * connecting ssh sessions */

	sftp_session		first;		/* first sftp session */

	char 			dst_path[PATH_MAX];
	struct list_head	src_list;
	struct list_head	path_list;
	struct chunk_pool	cp;

	pthread_t		tid_scan;	/* tid for scan thread */
	int			ret_scan;	/* return code from scan thread */

	size_t			total_bytes;	/* total bytes to be transferred */

	struct list_head	thread_list;
	rwlock			thread_rwlock;
};


struct mscp_thread {
	struct list_head	list;	/* mscp->thread_list */

	struct mscp	*m;
	int		id;
	sftp_session	sftp;
	pthread_t	tid;
	int		cpu;
	size_t		done;
	bool		finished;
	int		ret;
};

struct src {
	struct list_head list;	/* mscp->src_list */
	char *path;
};

#define DEFAULT_MIN_CHUNK_SZ    (64 << 20)      /* 64MB */
#define DEFAULT_NR_AHEAD        32
#define DEFAULT_BUF_SZ          16384
/* XXX: we use 16384 byte buffer pointed by
 * https://api.libssh.org/stable/libssh_tutor_sftp.html. The larget
 * read length from sftp_async_read is 65536 byte. Read sizes larger
 * than 65536 cause a situation where data remainds but
 * sftp_async_read returns 0.
 */

#define DEFAULT_MAX_STARTUPS	8

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
                mscp_set_error("failed to realloc: %s", strerrno());
                return -1;
        }

        nr_usable = 0;
        nr_all = 0;
        for (n = strlen(_coremask) - 1; n >=0; n--) {
                c[0] = _coremask[n];
                v = strtol(c, NULL, 16);
                if (v == LONG_MIN || v == LONG_MAX) {
                        mscp_set_error("invalid coremask: %s", coremask);
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
                                        mscp_set_error("realloc: %s", strerrno());
                                        return -1;
                                }
                                core_list[nr_usable - 1] = nr_all - 1;
                        }
                }
        }

        if (nr_usable < 1) {
                mscp_set_error("invalid core mask: %s", coremask);
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
		mscp_set_error("invalid nr_threads: %d", o->nr_threads);
		return -1;
	} else if (o->nr_threads == 0)
		o->nr_threads = default_nr_threads();

	if (o->nr_ahead < 0) {
		mscp_set_error("invalid nr_ahead: %d", o->nr_ahead);
		return -1;
	} else if (o->nr_ahead == 0)
		o->nr_ahead = DEFAULT_NR_AHEAD;

	if (o->min_chunk_sz == 0)
		o->min_chunk_sz = DEFAULT_MIN_CHUNK_SZ;
	else {
		if (o->min_chunk_sz < getpagesize() ||
		    o->min_chunk_sz % getpagesize() != 0) {
			mscp_set_error("min chunk size must be "
				       "larget than and multiple of page size %d: %lu",
				       getpagesize(), o->min_chunk_sz);
			return -1;
		}
	}

	if (o->max_chunk_sz) {
		if (o->max_chunk_sz < getpagesize() ||
		    o->max_chunk_sz % getpagesize() != 0) {
			mscp_set_error("min chunk size must be larget than and "
				       "multiple of page size %d: %lu",
				       getpagesize(), o->max_chunk_sz);
		}
		if (o->min_chunk_sz > o->max_chunk_sz) {
			mscp_set_error("smaller max chunk size than "
				       "min chunk size: %lu < %lu",
				       o->max_chunk_sz, o->min_chunk_sz);
			return -1;
		}
	}

	if (o->buf_sz == 0)
		o->buf_sz = DEFAULT_BUF_SZ;
	else if (o->buf_sz == 0) {
		mscp_set_error("invalid buf size: %lu", o->buf_sz);
		return -1;
	}

	if (o->max_startups == 0)
		o->max_startups = DEFAULT_MAX_STARTUPS;
	else if (o->max_startups < 0) {
		mscp_set_error("invalid max_startups: %d", o->max_startups);
		return -1;
	}

	if (o->msg_fd == 0)
		o->msg_fd = STDOUT_FILENO;

	return 0;
}

struct mscp *mscp_init(const char *remote_host, int direction,
		       struct mscp_opts *o, struct mscp_ssh_opts *s)
{
	struct mscp *m;
	int n;

	if (!remote_host) {
		mscp_set_error("empty remote host");
		return NULL;
	}

	if (!(direction == MSCP_DIRECTION_L2R ||
	      direction == MSCP_DIRECTION_R2L)) {
		mscp_set_error("invalid copy direction: %d", direction);
		return NULL;
	}

	mprint_set_severity(o->severity);

	if (validate_and_set_defaut_params(o) < 0) {
		return NULL;
	}

	m = malloc(sizeof(*m));
	if (!m) {
		mscp_set_error("failed to allocate memory: %s", strerrno());
		return NULL;
	}

	memset(m, 0, sizeof(*m));
	INIT_LIST_HEAD(&m->src_list);
	INIT_LIST_HEAD(&m->path_list);
	chunk_pool_init(&m->cp);

	INIT_LIST_HEAD(&m->thread_list);
	rwlock_init(&m->thread_rwlock);

	if ((m->sem = sem_create(o->max_startups)) == NULL) {
		mscp_set_error("sem_create: %s", strerrno());
		goto free_out;
	}

	m->remote = strdup(remote_host);
	if (!m->remote) {
		mscp_set_error("failed to allocate memory: %s", strerrno());
		goto free_out;
	}
	m->direction = direction;
	if (o->msg_fd > -1) {
		m->msg_fp = fdopen(o->msg_fd, "a");
		if (!m->msg_fp) {
			mscp_set_error("fdopen failed: %s", strerrno());
			goto free_out;
		}
	} else
		m->msg_fp = NULL;

	if (strlen(o->coremask) > 0) {
		if (expand_coremask(o->coremask, &m->cores, &m->nr_cores) < 0)
			goto free_out;
		mpr_notice(m->msg_fp, "usable cpu cores:");
		for (n = 0; n < m->nr_cores; n++)
			mpr_notice(m->msg_fp, " %d", m->cores[n]);
		mpr_notice(m->msg_fp, "\n");
	}

	m->opts = o;
	m->ssh_opts = s;

	return m;

free_out:
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
	struct src *s;

	s = malloc(sizeof(*s));
	if (!s) {
		mscp_set_error("failed to allocate memory: %s", strerrno());
		return -1;
	}

	memset(s, 0, sizeof(*s));
	s->path = strdup(src_path);
	if (!s->path) {
		mscp_set_error("failed to allocate memory: %s", strerrno());
		free(s);
		return -1;
	}

	list_add_tail(&s->list, &m->src_list);
	return 0;
}

int mscp_set_dst_path(struct mscp *m, const char *dst_path)
{
	if (strlen(dst_path) + 1 >= PATH_MAX) {
		mscp_set_error("too long dst path: %s", dst_path);
		return -1;
	}

	if (!non_null_string(dst_path))
		strncpy(m->dst_path, ".", 1);
	else
		strncpy(m->dst_path, dst_path, PATH_MAX);

	return 0;
}

static int get_page_mask(void)
{
        long page_sz = sysconf(_SC_PAGESIZE);
        size_t page_mask = 0;
        int n;

        for (n = 0; page_sz > 0; page_sz >>= 1, n++) {
                page_mask <<= 1;
                page_mask |= 1;
        }

        return page_mask >> 1;
}

static void mscp_stop_copy_thread(struct mscp *m)
{
	struct mscp_thread *t;

	RWLOCK_READ_ACQUIRE(&m->thread_rwlock);
	list_for_each_entry(t, &m->thread_list, list) {
		if (!t->finished)
			pthread_cancel(t->tid);
	}
	RWLOCK_RELEASE();
}

static void mscp_stop_scan_thread(struct mscp *m)
{
	if (m->tid_scan)
		pthread_cancel(m->tid_scan);
}

void mscp_stop(struct mscp *m)
{
	mscp_stop_scan_thread(m);
	mscp_stop_copy_thread(m);
}

void *mscp_scan_thread(void *arg)
{
	struct mscp *m = arg;
	sftp_session src_sftp = NULL, dst_sftp = NULL;
	struct path_resolve_args a;
	struct list_head tmp;
	struct path *p;
	struct src *s;
	struct stat ss, ds;
	glob_t pglob;
	int n;
	
	m->ret_scan = 0;

	switch (m->direction) {
	case MSCP_DIRECTION_L2R:
		src_sftp = NULL;
		dst_sftp = m->first;
		break;
	case MSCP_DIRECTION_R2L:
		src_sftp = m->first;
		dst_sftp = NULL;
		break;
	default:
		mscp_set_error("invalid copy direction: %d", m->direction);
		goto err_out;
	}

	/* initialize path_resolve_args */
	memset(&a, 0, sizeof(a));
	a.msg_fp = m->msg_fp;
	a.total_bytes = &m->total_bytes;

	if (list_count(&m->src_list) > 1)
		a.dst_path_should_dir = true;

	if (mscp_stat(m->dst_path, &ds, dst_sftp) == 0) {
		if (S_ISDIR(ds.st_mode))
			a.dst_path_is_dir = true;
	}

	a.cp = &m->cp;
	a.nr_conn = m->opts->nr_threads;
	a.min_chunk_sz = m->opts->min_chunk_sz;
	a.max_chunk_sz = m->opts->max_chunk_sz;
	a.chunk_align = get_page_mask();

	mpr_info(m->msg_fp, "start to walk source path(s)\n");

	/* walk a src_path recusively, and resolve path->dst_path for each src */
	list_for_each_entry(s, &m->src_list, list) {
		memset(&pglob, 0, sizeof(pglob));
		if (mscp_glob(s->path, GLOB_NOCHECK, &pglob, src_sftp) < 0) {
			mscp_set_error("mscp_glob: %s", strerrno());
			goto err_out;
		}

		for (n = 0; n < pglob.gl_pathc; n++) {
			if (mscp_stat(pglob.gl_pathv[n], &ss, src_sftp) < 0) {
				mscp_set_error("stat: %s %s", s->path, strerrno());
				goto err_out;
			}

			if (!a.dst_path_should_dir && pglob.gl_pathc > 1)
				a.dst_path_should_dir = true; /* we have over 1 src */

			/* set path specific args */
			a.src_path = pglob.gl_pathv[n];
			a.dst_path = m->dst_path;
			a.src_path_is_dir = S_ISDIR(ss.st_mode);

			INIT_LIST_HEAD(&tmp);
			if (walk_src_path(src_sftp, pglob.gl_pathv[n], &tmp, &a) < 0)
				goto err_out;

			list_splice_tail(&tmp, m->path_list.prev);
		}
		mscp_globfree(&pglob);
	}

	mpr_info(m->msg_fp, "walk source path(s) done\n");
	chunk_pool_set_filled(&m->cp);
	m->ret_scan = 0;
	return NULL;

err_out:
	chunk_pool_set_filled(&m->cp);
	m->ret_scan = -1;
	return NULL;
}

int mscp_scan(struct mscp *m)
{
	int ret = pthread_create(&m->tid_scan, NULL, mscp_scan_thread, m);
	if (ret < 0) {
		mscp_set_error("pthread_create_error: %d", ret);
		m->tid_scan = 0;
		mscp_stop(m);
		return -1;
	}

	/* We wait for there are over nr_threads chunks to determine
	 * actual number of threads (and connections), or scan
	 * finished. If the number of chunks are smaller than
	 * nr_threads, we adjust nr_threads to the number of chunks.
	 */
	while (!chunk_pool_is_filled(&m->cp) &&
	       chunk_pool_size(&m->cp) < m->opts->nr_threads)
		usleep(100);

	return 0;
}

int mscp_scan_join(struct mscp *m)
{
	if (m->tid_scan) {
		pthread_join(m->tid_scan, NULL);
		m->tid_scan = 0;
		return m->ret_scan;
	}
	return 0;
}



static void *mscp_copy_thread(void *arg);

static struct mscp_thread *mscp_copy_thread_spawn(struct mscp *m, int id)
{
	struct mscp_thread *t;
	int ret;

	t = malloc(sizeof(*t));
	if (!t){
		mscp_set_error("malloc: %s,", strerrno());
		return NULL;
	}

	memset(t, 0, sizeof(*t));
	t->m = m;
	t->id = id;
	if (m->cores == NULL)
		t->cpu = -1;	/* not pinned to cpu */
	else
		t->cpu = m->cores[id % m->nr_cores];

	ret = pthread_create(&t->tid, NULL, mscp_copy_thread, t);
	if (ret < 0) {
		mscp_set_error("pthread_create error: %d", ret);
		free(t);
		return NULL;
	}

	return t;
}


int mscp_start(struct mscp *m)
{
	struct mscp_thread *t;
	int n, ret = 0;

	if ((n = chunk_pool_size(&m->cp)) < m->opts->nr_threads) {
		mpr_notice(m->msg_fp, "we have only %d chunk(s). "
			   "set number of connections to %d\n", n, n);
		m->opts->nr_threads = n;
	}

	for (n = 0; n < m->opts->nr_threads; n++) {
		t = mscp_copy_thread_spawn(m, n);
		if (!t) {
			mpr_err(m->msg_fp, "failed to spawn copy thread\n");
			break;
		}
		RWLOCK_WRITE_ACQUIRE(&m->thread_rwlock);
		list_add_tail(&t->list, &m->thread_list);
		RWLOCK_RELEASE();
        }

	return n;
}

int mscp_join(struct mscp *m)
{
	struct mscp_thread *t;
	int n, ret = 0;

	/* waiting for scan thread joins... */
	ret = mscp_scan_join(m);

        /* waiting for copy threads join... */
	RWLOCK_READ_ACQUIRE(&m->thread_rwlock);
	list_for_each_entry(t, &m->thread_list, list) {
		pthread_join(t->tid, NULL);
		if (t->ret < 0)
			ret = t->ret;
		if (t->sftp) {
			ssh_sftp_close(t->sftp);
			t->sftp = NULL;
		}
	}
	RWLOCK_RELEASE();

        if (m->first) {
                ssh_sftp_close(m->first);
		m->first = NULL;
	}

	return ret;
}

/* copy thread related functions */

static void mscp_copy_thread_cleanup(void *arg)
{
        struct mscp_thread *t = arg;
        t->finished = true;
}

void *mscp_copy_thread(void *arg)
{
        sftp_session src_sftp, dst_sftp;
        struct mscp_thread *t = arg;
	struct mscp *m = t->m;
        struct chunk *c;

        if (t->cpu > -1) {
                if (set_thread_affinity(pthread_self(), t->cpu) < 0) {
			t->ret = -1;
                        return NULL;
		}
        }

	if (sem_wait(m->sem) < 0) {
		mscp_set_error("sem_wait: %s", strerrno());
		mpr_err(m->msg_fp, "%s", mscp_get_error());
		goto err_out;
	}

	mpr_notice(m->msg_fp, "connecting to %s for a copy thread[%d]...\n",
		   m->remote, t->id);
	t->sftp = ssh_init_sftp_session(m->remote, m->ssh_opts);

	if (sem_post(m->sem) < 0) {
		mscp_set_error("sem_post: %s", strerrno());
		mpr_err(m->msg_fp, "%s", mscp_get_error());
		goto err_out;
	}

	if (!t->sftp) {
		mpr_err(m->msg_fp, "copy thread[%d]: %s\n", t->id, mscp_get_error());
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
                return NULL; /* not reached */
        }

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        pthread_cleanup_push(mscp_copy_thread_cleanup, t);

        while (1) {
                c = chunk_pool_pop(&m->cp);
		if (c == CHUNK_POP_WAIT) {
			usleep(100); /* XXX: hard code */
			continue;
		}

                if (!c)
                        break; /* no more chunks */

		if ((t->ret = copy_chunk(m->msg_fp,
					 c, src_sftp, dst_sftp, m->opts->nr_ahead,
					 m->opts->buf_sz, &t->done)) < 0)
			break;
        }

        pthread_cleanup_pop(1);

        if (t->ret < 0)
		mpr_err(m->msg_fp, "copy failed: chunk %s 0x%010lx-0x%010lx\n",
			c->p->path, c->off, c->off + c->len);

        return NULL;

err_out:
	t->finished = true;
	t->ret = -1;
	return NULL;
}


/* cleanup related functions */

static void free_src(struct list_head *list)
{
	struct src *s;
	s = list_entry(list, typeof(*s), list);
	free(s->path);
	free(s);
}

static void free_path(struct list_head *list)
{
	struct path *p;
	p = list_entry(list, typeof(*p), list);
	free(p);
}

static void free_chunk(struct list_head *list)
{
	struct chunk *c;
	c = list_entry(list, typeof(*c), list);
	free(c);
}

static void free_thread(struct list_head *list)
{
	struct mscp_thread *t;
	t = list_entry(list, typeof(*t), list);
	free(t);
}

void mscp_cleanup(struct mscp *m)
{
        if (m->first) {
                ssh_sftp_close(m->first);
		m->first = NULL;
	}

	list_free_f(&m->src_list, free_src);
	INIT_LIST_HEAD(&m->src_list);

	list_free_f(&m->path_list, free_path);
	INIT_LIST_HEAD(&m->path_list);

	chunk_pool_release(&m->cp);
	chunk_pool_init(&m->cp);

	RWLOCK_WRITE_ACQUIRE(&m->thread_rwlock);
	list_free_f(&m->thread_list, free_thread);
	RWLOCK_RELEASE();
}

void mscp_free(struct mscp *m)
{
	mscp_cleanup(m);
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
	bool finished = true;

	s->total = m->total_bytes;
	s->done = 0;

	RWLOCK_READ_ACQUIRE(&m->thread_rwlock);
	list_for_each_entry(t, &m->thread_list, list) {
		s->done += t->done;
		if (!t->finished)
			finished = false;
	}
	RWLOCK_RELEASE();

	s->finished = finished;
}
