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
	char			*remote;	/* remote host (and uername) */
	struct mscp_opts	*opts;
	struct mscp_ssh_opts	*ssh_opts;

	int			 *cores;	/* usable cpu cores by COREMASK */
	int			 nr_cores;	/* length of array of cores */

	sftp_session		first;		/* first sftp session */

	char 			dst_path[PATH_MAX];
	struct list_head	src_list;
	struct list_head	path_list;
	struct list_head	chunk_list;
	lock			chunk_lock;

	struct mscp_thread	*threads;
};

__thread struct mscp *m_local; /* mscp instance for this
				* process/thread. it is used for
				* sighandler SIGINT and print stats */

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
                pr_err("failed to realloc: %s\n", strerrno());
                return -1;
        }

        nr_usable = 0;
        nr_all = 0;
        for (n = strlen(_coremask) - 1; n >=0; n--) {
                c[0] = _coremask[n];
                v = strtol(c, NULL, 16);
                if (v == LONG_MIN || v == LONG_MAX) {
                        pr_err("invalid coremask: %s\n", coremask);
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
                                        pr_err("failed to realloc: %s\n", strerrno());
                                        return -1;
                                }
                                core_list[nr_usable - 1] = nr_all - 1;
                        }
                }
        }

        if (nr_usable < 1) {
                pr_err("invalid core mask: %s\n", coremask);
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
	if (!(o->direction == MSCP_DIRECTION_L2R ||
	      o->direction == MSCP_DIRECTION_R2L)) {
		pr_err("invalid copy direction: %d\n", o->direction);
		return -1;
	}

	if (o->nr_threads < 0) {
		pr_err("invalid nr_threads: %d\n", o->nr_threads);
		return -1;
	} else if (o->nr_threads == 0)
		o->nr_threads = default_nr_threads();

	if (o->nr_ahead < 0) {
		pr_err("invalid nr_ahead: %d\n", o->nr_ahead);
		return -1;
	} else if (o->nr_ahead == 0)
		o->nr_ahead = DEFAULT_NR_AHEAD;

	if (o->min_chunk_sz == 0)
		o->min_chunk_sz = DEFAULT_MIN_CHUNK_SZ;
	else {
		if (o->min_chunk_sz < getpagesize() ||
		    o->min_chunk_sz % getpagesize() != 0) {
			pr_err("min chunk size must be "
			       "larget than and multiple of page size %d: %lu\n",
			       getpagesize(), o->min_chunk_sz);
			return -1;
		}
	}

	if (o->max_chunk_sz) {
		if (o->max_chunk_sz < getpagesize() ||
		    o->max_chunk_sz % getpagesize() != 0) {
			pr_err("min chunk size must be "
			       "larget than and multiple of page size %d: %lu\n",
			       getpagesize(), o->max_chunk_sz);
		}
		if (o->min_chunk_sz > o->max_chunk_sz) {
			pr_err("smaller max chunk size than min chunk size: %lu < %lu\n",
			       o->max_chunk_sz, o->min_chunk_sz);
			return -1;
		}
	}

	if (o->buf_sz == 0)
		o->buf_sz = DEFAULT_BUF_SZ;
	else if (o->buf_sz == 0) {
		pr_err("invalid buf size: %lu\n", o->buf_sz);
		return -1;
	}

	return 0;
}

struct mscp *mscp_init(const char *remote_host,
		       struct mscp_opts *o, struct mscp_ssh_opts *s)
{
	struct mscp *m;
	int n;

	m = malloc(sizeof(*m));
	if (!m) {
		pr_err("failed to allocate memory: %s\n", strerrno());
		return NULL;
	}

	if (validate_and_set_defaut_params(o) < 0)
		goto free_out;

	memset(m, 0, sizeof(*m));
	INIT_LIST_HEAD(&m->src_list);
	INIT_LIST_HEAD(&m->path_list);
	INIT_LIST_HEAD(&m->chunk_list);
	lock_init(&m->chunk_lock);
	m->remote = strdup(remote_host);
	if (!m->remote) {
		pr_err("failed to allocate memory: %s\n", strerrno());
		goto free_out;
	}

	if (strlen(o->coremask) > 0) {
		if (expand_coremask(o->coremask, &m->cores, &m->nr_cores) < 0)
			goto free_out;
		pprint(1, "usable cpu cores:");
		for (n = 0; n < m->nr_cores; n++)
			pprint(2, " %d", m->cores[n]);
		pprint(1, "\n");
	}

	m->opts = o;
	m->ssh_opts = s;

	pprint_set_level(o->verbose_level);

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

int mscp_set_dst_path(struct mscp *m, const char *dst_path)
{
	if (strlen(dst_path) + 1 >= PATH_MAX) {
		pr_err("too long dst path: %s\n", dst_path);
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
	bool src_path_is_dir, dst_path_is_dir, dst_path_should_dir = false;
	struct list_head tmp;
	struct src *s;
	mstat ss, ds;
	
	switch (m->opts->direction) {
	case MSCP_DIRECTION_L2R:
		src_sftp = NULL;
		dst_sftp = m->first;
		break;
	case MSCP_DIRECTION_R2L:
		src_sftp = m->first;
		dst_sftp = NULL;
		break;
	default:
		pr_err("invalid copy direction: %d\n", m->opts->direction);
		return -1;
	}

	if (list_count(&m->src_list) > 1)
		dst_path_should_dir = true;

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
		
		if (list_count(&tmp) > 1)
			dst_path_should_dir = true;

		if (resolve_dst_path(s->path, m->dst_path, &tmp,
				     src_path_is_dir, dst_path_is_dir,
				     dst_path_should_dir) < 0)
			return -1;

		list_splice_tail(&tmp, m->path_list.prev);
	}

	if (resolve_chunk(&m->path_list, &m->chunk_list, m->opts->nr_threads,
			  m->opts->max_chunk_sz, m->opts->min_chunk_sz) < 0)
		return -1;

	return 0;
}


static void *mscp_copy_thread(void *arg);
static int mscp_stat_init();
static void mscp_stat_final();

static void stop_copy_threads(int sig)
{
	struct mscp *m = m_local;
        int n;

        pr("stopping...\n");
        for (n = 0; n < m->opts->nr_threads; n++) {
                if (m->threads[n].tid && !m->threads[n].finished)
                        pthread_cancel(m->threads[n].tid);
        }
}

int mscp_start(struct mscp *m)
{
	int n, ret;

	/* set this mscp instance to thread local storage.  after
	 * spawning threads, this thread waits for joining copy theads
	 * and print stats by SIGALRM.
	 */
	m_local = m;

	if ((n = list_count(&m->chunk_list)) < m->opts->nr_threads) {
		pprint1("we have only %d chunk(s). "
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
			pprint2("connecting to %s for a copy thread...\n", m->remote);
			t->sftp = ssh_init_sftp_session(m->remote, m->ssh_opts);
			if (!t->sftp)
				return -1;
		}
	}

        /* init mscp stat for printing progress bar */
        if (mscp_stat_init() < 0) {
                ret = 1;
                goto out;
        }

        /* spawn copy threads */
        for (n = 0; n < m->opts->nr_threads; n++) {
                struct mscp_thread *t = &m->threads[n];
                ret = pthread_create(&t->tid, NULL, mscp_copy_thread, t);
                if (ret < 0) {
                        pr_err("pthread_create error: %d\n", ret);
                        stop_copy_threads(0);
                        ret = 1;
                        goto join_out;
                }
        }

        /* register SIGINT to stop threads */
        if (signal(SIGINT, stop_copy_threads) == SIG_ERR) {
                pr_err("cannot set signal: %s\n", strerrno());
                ret = 1;
                goto out;
        }

join_out:
        /* waiting for threads join... */
        for (n = 0; n < m->opts->nr_threads; n++) {
                if (m->threads[n].tid) {
                        pthread_join(m->threads[n].tid, NULL);
                        if (m->threads[n].ret < 0)
                                ret = m->threads[n].ret;
                }
        }

        /* print final result */
        mscp_stat_final();

out:
        if (m->first)
                ssh_sftp_close(m->first);

        if (m->threads) {
                for (n = 0; n < m->opts->nr_threads; n++) {
                        struct mscp_thread *t = &m->threads[n];
                        if (t->sftp)
                                ssh_sftp_close(t->sftp);
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

        switch (m->opts->direction) {
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

                if ((t->ret = prepare_dst_path(c->p, dst_sftp)) < 0)
                        break;

		if ((t->ret = copy_chunk(c, src_sftp, dst_sftp, m->opts->nr_ahead,
					 m->opts->buf_sz, &t->done)) < 0)
			break;
        }

        pthread_cleanup_pop(1);

        if (t->ret < 0)
                pr_err("copy failed: chunk %s 0x%010lx-0x%010lx\n",
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

/* progress bar-related functions */

double calculate_timedelta(struct timeval *b, struct timeval *a)
{
        double sec, usec;

        if (a->tv_usec < b->tv_usec) {
                a->tv_usec += 1000000;
                a->tv_sec--;
        }

        sec = a->tv_sec - b->tv_sec;
        usec = a->tv_usec - b->tv_usec;
        sec += usec / 1000000;

        return sec;
}


static double calculate_bps(size_t diff, struct timeval *b, struct timeval *a)
{
        return (double)diff / calculate_timedelta(b, a);
}

static char *calculate_eta(size_t remain, size_t diff,
			   struct timeval *b, struct timeval *a)
{
        static char buf[16];
        double elapsed = calculate_timedelta(b, a);
        double eta;

        if (diff == 0)
                snprintf(buf, sizeof(buf), "--:-- ETA");
        else {
                eta = remain / (diff / elapsed);
                snprintf(buf, sizeof(buf), "%02d:%02d ETA",
                         (int)floor(eta / 60), (int)round(eta) % 60);
        }
        return buf;
}

static void print_progress_bar(double percent, char *suffix)
{
        int n, thresh, bar_width;
        struct winsize ws;
        char buf[128];

        /*
         * [=======>   ] XX% SUFFIX
         */

        buf[0] = '\0';

        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0)
                return; /* XXX */
        bar_width = min(sizeof(buf), ws.ws_col) - strlen(suffix) - 7;

        memset(buf, 0, sizeof(buf));
        if (bar_width > 8) {
                thresh = floor(bar_width * (percent / 100)) - 1;

                for (n = 1; n < bar_width - 1; n++) {
                        if (n <= thresh)
                                buf[n] = '=';
                        else
                                buf[n] = ' ';
                }
                buf[thresh] = '>';
                buf[0] = '[';
                buf[bar_width - 1] = ']';
                snprintf(buf + bar_width, sizeof(buf) - bar_width,
                         " %3d%% ", (int)floor(percent));
        }

        pprint0("%s%s", buf, suffix);
}

static void print_progress(struct timeval *b, struct timeval *a,
			   size_t total, size_t last, size_t done)
{
        char *bps_units[] = { "B/s ", "KB/s", "MB/s", "GB/s" };
        char *byte_units[] = { "B ", "KB", "MB", "GB", "TB", "PB" };
        char suffix[128];
        int bps_u, byte_tu, byte_du;
        size_t total_round, done_round;
        int percent;
        double bps;

#define array_size(a) (sizeof(a) / sizeof(a[0]))

        if (total <= 0) {
                pprint1("total 0 byte transferred");
                return; /* copy 0-byte file(s) */
        }

        total_round = total;
        for (byte_tu = 0; total_round > 1000 && byte_tu < array_size(byte_units) - 1;
             byte_tu++)
                total_round /= 1024;

        bps = calculate_bps(done - last, b, a);
        for (bps_u = 0; bps > 1000 && bps_u < array_size(bps_units); bps_u++)
                bps /= 1000;

        percent = floor(((double)(done) / (double)total) * 100);

        done_round = done;
        for (byte_du = 0; done_round > 1000 && byte_du < array_size(byte_units) - 1;
             byte_du++)
                done_round /= 1024;

        snprintf(suffix, sizeof(suffix), "%4lu%s/%lu%s %6.1f%s  %s",
                 done_round, byte_units[byte_du], total_round, byte_units[byte_tu],
                 bps, bps_units[bps_u], calculate_eta(total - done, done - last, b, a));

        print_progress_bar(percent, suffix);
}


struct xfer_stat {
        struct timeval start, before, after;
        size_t total;
        size_t last;
        size_t done;
};
__thread struct xfer_stat s;

static void mscp_stat_handler(int signum)
{
	struct mscp *m = m_local;
        int n;

        for (s.done = 0, n = 0; n < m->opts->nr_threads; n++)
                s.done += m->threads[n].done;

        gettimeofday(&s.after, NULL);
        if (signum == SIGALRM) {
                alarm(1);
                print_progress(&s.before, &s.after, s.total, s.last, s.done);
                s.before = s.after;
                s.last = s.done;
        } else {
                /* called from mscp_stat_final. calculate progress from the beginning */
                print_progress(&s.start, &s.after, s.total, 0, s.done);
                pprint(0, "\n"); /* this is final output. */
        }
}

static int mscp_stat_init()
{
	struct mscp *m = m_local;
        struct path *p;

        memset(&s, 0, sizeof(s));
        list_for_each_entry(p, &m->path_list, list) {
                s.total += p->size;
        }

        if (signal(SIGALRM, mscp_stat_handler) == SIG_ERR) {
                pr_err("signal: %s\n", strerrno());
                return -1;
        }

        gettimeofday(&s.start, NULL);
        s.before = s.start;
        alarm(1);

        return 0;
}

static void mscp_stat_final()
{
        alarm(0);
        mscp_stat_handler(0);
}
