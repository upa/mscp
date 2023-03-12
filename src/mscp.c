#include <stdbool.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>


#include <list.h>       
#include <util.h>       
#include <ssh.h>                
#include <path.h>
#include <atomic.h>             
#include <platform.h>
#include <message.h>
#include <mscp.h>

struct mscp {
	char			*remote;	/* remote host (and uername) */
	int			direction;	/* copy direction */
	struct mscp_opts	*opts;
	struct mscp_ssh_opts	*ssh_opts;

	int			msg_fd;		/* writer fd for message pipe */

	int			 *cores;	/* usable cpu cores by COREMASK */
	int			 nr_cores;	/* length of array of cores */

	sftp_session		first;		/* first sftp session */

	char 			dst_path[PATH_MAX];
	struct list_head	src_list;
	struct list_head	path_list;
	struct list_head	chunk_list;
	lock			chunk_lock;

	size_t			total_bytes;	/* total bytes to be transferred */
	struct mscp_thread	*threads;
};


struct mscp_thread {
	struct mscp	*m;
	sftp_session	sftp;
	pthread_t	tid;
	int		cpu;
	size_t		done;
	bool		finished;
	int		ret;
};

struct src {
	struct list_head list;
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

	return 0;
}

struct mscp *mscp_init(const char *remote_host, int direction,
		       struct mscp_opts *o, struct mscp_ssh_opts *s)
{
	struct mscp *m;
	int n;

	if (!remote_host) {
		mscp_set_error("empty remote host\n");
		return NULL;
	}

	if (!(direction == MSCP_DIRECTION_L2R ||
	      direction == MSCP_DIRECTION_R2L)) {
		mscp_set_error("invalid copy direction: %d", direction);
		return NULL;
	}

	m = malloc(sizeof(*m));
	if (!m) {
		mscp_set_error("failed to allocate memory: %s", strerrno());
		return NULL;
	}

	mprint_set_severity(o->severity);

	if (validate_and_set_defaut_params(o) < 0)
		goto free_out;

	memset(m, 0, sizeof(*m));
	INIT_LIST_HEAD(&m->src_list);
	INIT_LIST_HEAD(&m->path_list);
	INIT_LIST_HEAD(&m->chunk_list);
	lock_init(&m->chunk_lock);

	m->remote = strdup(remote_host);
	if (!m->remote) {
		mscp_set_error("failed to allocate memory: %s", strerrno());
		goto free_out;
	}
	m->direction = direction;
	m->msg_fd = o->msg_fd;

	if (strlen(o->coremask) > 0) {
		if (expand_coremask(o->coremask, &m->cores, &m->nr_cores) < 0)
			goto free_out;
		mpr_notice(m->msg_fd, "usable cpu cores:");
		for (n = 0; n < m->nr_cores; n++)
			mpr_notice(m->msg_fd, " %d", m->cores[n]);
		mpr_notice(m->msg_fd, "\n");
	}

	m->opts = o;
	m->ssh_opts = s;

	return m;

free_out:
	free(m);
	return NULL;
}

void mscp_set_msg_fd(struct mscp *m, int fd)
{
	m->msg_fd = fd;
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


int mscp_prepare(struct mscp *m)
{
	sftp_session src_sftp = NULL, dst_sftp = NULL;
	bool src_path_is_dir, dst_path_is_dir, dst_path_should_dir;
	struct list_head tmp;
	struct path *p;
	struct src *s;
	mstat ss, ds;
	
	src_path_is_dir = dst_path_is_dir = dst_path_should_dir = false;

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
		return -1;
	}

	if (list_count(&m->src_list) > 1)
		dst_path_should_dir = true;

	if (mscp_stat(m->dst_path, &ds, dst_sftp) == 0) {
		if (mstat_is_dir(ds))
			dst_path_is_dir = true;
		mscp_stat_free(ds);
	}

	/* walk a src_path recusively, and resolve path->dst_path for each src */
	list_for_each_entry(s, &m->src_list, list) {
		if (mscp_stat(s->path, &ss, src_sftp) < 0) {
			mscp_set_error("stat: %s", mscp_strerror(src_sftp));
			return -1;
		}
		src_path_is_dir = mstat_is_dir(ss);
		mscp_stat_free(ss);

		INIT_LIST_HEAD(&tmp);
		if (walk_src_path(src_sftp, s->path, &tmp) < 0)
			return -1;
		
		if (list_count(&tmp) > 1)
			dst_path_should_dir = true;

		if (resolve_dst_path(m->msg_fd, s->path, m->dst_path, &tmp,
				     src_path_is_dir, dst_path_is_dir,
				     dst_path_should_dir) < 0)
			return -1;

		list_splice_tail(&tmp, m->path_list.prev);
	}

	if (resolve_chunk(&m->path_list, &m->chunk_list, m->opts->nr_threads,
			  m->opts->min_chunk_sz, m->opts->max_chunk_sz) < 0)
		return -1;

	/* save total bytes to be transferred */
	m->total_bytes = 0;
	list_for_each_entry(p, &m->path_list, list) {
		m->total_bytes += p->size;
	}

	return 0;
}

void mscp_stop(struct mscp *m)
{
	int n;
        pr("stopping...\n");
        for (n = 0; n < m->opts->nr_threads; n++) {
                if (m->threads[n].tid && !m->threads[n].finished)
                        pthread_cancel(m->threads[n].tid);
        }
}


static void *mscp_copy_thread(void *arg);

int mscp_start(struct mscp *m)
{
	int n, ret;

	if ((n = list_count(&m->chunk_list)) < m->opts->nr_threads) {
		mpr_notice(m->msg_fd, "we have only %d chunk(s). "
			   "set number of connections to %d\n", n, n);
		m->opts->nr_threads = n;
	}

	/* prepare thread instances */
	m->threads = calloc(m->opts->nr_threads, sizeof(struct mscp_thread));
	memset(m->threads, 0, m->opts->nr_threads * sizeof(struct mscp_thread));
	for (n = 0; n < m->opts->nr_threads; n++) {
		struct mscp_thread *t = &m->threads[n];
		t->m = m;
		if (!m->cores)
			t->cpu = -1;
		else
			t->cpu = m->cores[n % m->nr_cores];

		if (n == 0) {
			t->sftp = m->first; /* reuse first sftp session */
			m->first = NULL;
		}
		else {
			mpr_notice(m->msg_fd, "connecting to %s for a copy thread...\n",
				   m->remote);
			t->sftp = ssh_init_sftp_session(m->remote, m->ssh_opts);
			if (!t->sftp)
				return -1;
		}
	}

        /* spawn copy threads */
        for (n = 0; n < m->opts->nr_threads; n++) {
                struct mscp_thread *t = &m->threads[n];
                ret = pthread_create(&t->tid, NULL, mscp_copy_thread, t);
                if (ret < 0) {
                        mscp_set_error("pthread_create error: %d", ret);
                        mscp_stop(m);
			return -1;
                }
        }

	return 0;
}

int mscp_join(struct mscp *m)
{
	int n, ret = 0;

        /* waiting for threads join... */
        for (n = 0; n < m->opts->nr_threads; n++) {
                if (m->threads[n].tid) {
                        pthread_join(m->threads[n].tid, NULL);
                        if (m->threads[n].ret < 0)
                                ret = m->threads[n].ret;
                }
        }

        if (m->first) {
                ssh_sftp_close(m->first);
		m->first = NULL;
	}

        if (m->threads) {
                for (n = 0; n < m->opts->nr_threads; n++) {
                        struct mscp_thread *t = &m->threads[n];
			if (t->ret != 0)
				ret = ret;

                        if (t->sftp) {
                                ssh_sftp_close(t->sftp);
				t->sftp = NULL;
			}
                }
        }

	return ret;
}

/* copy thread related functions */

struct chunk *acquire_chunk(struct list_head *chunk_list)
{
        /* under the lock for chunk_list */
        struct list_head *first = chunk_list->next;
        struct chunk *c = NULL;

        if (list_empty(chunk_list))
                return NULL; /* list is empty */

        c = list_entry(first, struct chunk, list);
        list_del(first);
        return c;
}

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

        if (t->cpu > -1) {
                if (set_thread_affinity(pthread_self(), t->cpu) < 0)
                        return NULL;
        }

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        pthread_cleanup_push(mscp_copy_thread_cleanup, t);

        while (1) {
                LOCK_ACQUIRE_THREAD(&m->chunk_lock);
                c = acquire_chunk(&m->chunk_list);
                LOCK_RELEASE_THREAD();

                if (!c)
                        break; /* no more chunks */

		if ((t->ret = copy_chunk(m->msg_fd,
					 c, src_sftp, dst_sftp, m->opts->nr_ahead,
					 m->opts->buf_sz, &t->done)) < 0)
			break;
        }

        pthread_cleanup_pop(1);

        if (t->ret < 0)
                mscp_set_error("copy failed: chunk %s 0x%010lx-0x%010lx",
			       c->p->path, c->off, c->off + c->len);

        return NULL;
}


/* cleanup related functions */

static void release_list(struct list_head *head, void (*f)(struct list_head*))
{
	struct list_head *p, *n;

	list_for_each_safe(p, n, head) {
		list_del(p);
		f(p);
	}
}

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

void mscp_cleanup(struct mscp *m)
{
        if (m->first) {
                ssh_sftp_close(m->first);
		m->first = NULL;
	}

	release_list(&m->src_list, free_src);
	INIT_LIST_HEAD(&m->src_list);

	release_list(&m->chunk_list, free_chunk);
	INIT_LIST_HEAD(&m->chunk_list);

	release_list(&m->path_list, free_path);
	INIT_LIST_HEAD(&m->path_list);

	if (m->threads) {
		free(m->threads);
		m->threads = NULL;
	}
}

void mscp_free(struct mscp *m)
{
	mscp_cleanup(m);
	if (m->remote)
		free(m->remote);
	if (m->cores)
		free(m->cores);
	free(m);
}

void mscp_get_stats(struct mscp *m, struct mscp_stats *s)
{
	bool finished = true;
	int n;

	s->total = m->total_bytes;
	for (s->done = 0, n = 0; n < m->opts->nr_threads; n++) {
		s->done += m->threads[n].done;

		if (!m->threads[n].done)
			finished = false;
	}

	s->finished = finished;
}
