#include <stdio.h>
#include <stdlib.h>
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
#include <file.h>
#include <pprint.h>
#include <atomic.h>
#include <platform.h>

#ifndef _VERSION /* passed through cmake */
#define VERSION "(unknown)"
#else
#define VERSION _VERSION
#endif

#define DEFAULT_MIN_CHUNK_SZ    (64 << 20)      /* 64MB */
#define DEFAULT_SFTP_BUF_SZ     131072          /* derived from qemu/block/ssh.c */
#define DEFAULT_IO_BUF_SZ       DEFAULT_SFTP_BUF_SZ
/* XXX: need to investigate max buf size for sftp_read/sftp_write */
#define DEFAULT_NR_AHEAD	16

struct mscp_thread {
	sftp_session    sftp;

	pthread_t       tid;
	int		cpu;
	size_t          done;           /* copied bytes */
	bool            finished;
	int		ret;
};

struct mscp {
	char                    *host;  /* remote host (and username) */
	struct ssh_opts         *opts;  /* ssh parameters */
	sftp_session            ctrl;   /* control sftp session */

	struct list_head        file_list;
	struct list_head        chunk_list;	/* stack of chunks */
	lock                    chunk_lock;	/* lock for chunk list */

	char    *target;

	int	nr_threads;	/* number of threads */
	int     sftp_buf_sz, io_buf_sz;
	int	nr_ahead;	/* # of ahead read command for remote to local copy */

	struct mscp_thread *threads;
} m;

void *mscp_copy_thread(void *arg);
int mscp_stat_init();
void mscp_stat_final();



void stop_copy_threads(int sig)
{
	int n;

	pr("stopping...\n");
	for (n = 0; n < m.nr_threads; n++) {
		if (!m.threads[n].finished)
			pthread_cancel(m.threads[n].tid);
	}
}

void usage(bool print_help) {
	printf("mscp v" VERSION ": copy files over multiple ssh connections\n"
	       "\n"
	       "Usage: mscp [vqDCHdh] [-n nr_conns] [-m coremask]\n"
	       "            [-s min_chunk_sz] [-S max_chunk_sz] [-a nr_ahead]\n"
#ifndef ASYNC_WRITE
	       "            [-b sftp_buf_sz] [-B io_buf_sz] \n"
#endif
	       "            [-l login_name] [-p port] [-i identity_file]\n"
	       "            [-c cipher_spec] source ... target\n"
	       "\n");

	if (!print_help)
		return;

	printf("    -n NR_CONNECTIONS  number of connections (default: half of # of cpu cores)\n"
	       "    -m COREMASK        hex value to specify cores where threads pinned\n"
	       "    -s MIN_CHUNK_SIZE  min chunk size (default: 64MB)\n"
	       "    -S MAX_CHUNK_SIZE  max chunk size (default: filesize / nr_conn)\n"
	       "\n"
	       "    -a NR_AHEAD        number of inflight SFTP commands (default: 16)\n"
#ifndef ASYNC_WRITE
	       "    -b SFTP_BUF_SIZE   buf size for sftp_read/write (default 131072B)\n"
	       "    -B IO_BUF_SIZE     buf size for read/write (default 131072B)\n"
	       "                       Note that the default value is derived from\n"
	       "                       qemu/block/ssh.c. need investigation...\n"
	       "                       -b and -B affect only local to remote copy\n"
#endif
	       "\n"
	       "    -v                 increment verbose output level\n"
	       "    -q                 disable output\n"
	       "    -D                 dry run\n"
	       "\n"
	       "    -l LOGIN_NAME      login name\n"
	       "    -p PORT            port number\n"
	       "    -i IDENTITY        identity file for public key authentication\n"
	       "    -c CIPHER          cipher spec, see `ssh -Q cipher`\n"
	       "    -C                 enable compression on libssh\n"
	       "    -H                 disable hostkey check\n"
	       "    -d                 increment ssh debug output level\n"
	       "    -h                 print this help\n"
	       "\n");
}

char *find_hostname(int ind, int argc, char **argv)
{
	char *h, *hostnames[argc];
	int n, cnt = 0;

	for (n = ind; n < argc; n++) {
		h = file_find_hostname(argv[n]);
		if (h)
			hostnames[cnt++] = h;
	}

	if (cnt == 0)
		return NULL;

	/* check all hostnames are identical */
	for (n = 1; n < cnt; n++) {
		int s1 = strlen(hostnames[n - 1]);
		int s2 = strlen(hostnames[n]);
		if (s1 != s2) {
			pr_err("different hostnames: %s and %s\n",
			       hostnames[n - 1], hostnames[n]);
			goto err_out;
		}
		if (strncmp(hostnames[n - 1], hostnames[n], s1) != 0) {
			pr_err("different hostnames: %s and %s\n",
			       hostnames[n - 1], hostnames[n]);
			goto err_out;
		}
	}

	for (n = 1; n < cnt; n++) {
		free(hostnames[n]);
	}

	return hostnames[0];

err_out:
	for (n = 0; n < cnt; n++) {
		free(hostnames[n]);
	}
	return NULL;
}

int expand_coremask(const char *coremask, int **cores, int *nr_cores)
{
	int n, *core_list, core_list_len = 0, nr_usable, nr_all;
	char c[2] = { 'x', '\0' };
	const char *_coremask;
	long v, needle;

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

int main(int argc, char **argv)
{
	struct ssh_opts opts;
	int min_chunk_sz = DEFAULT_MIN_CHUNK_SZ;
	int max_chunk_sz = 0;
	char *coremask = NULL;;
	int verbose = 1;
	bool dryrun = false;
	int ret = 0, n;
	int *cores, nr_cores;
	char ch;

	memset(&opts, 0, sizeof(opts));
	memset(&m, 0, sizeof(m));
	INIT_LIST_HEAD(&m.file_list);
	INIT_LIST_HEAD(&m.chunk_list);
	lock_init(&m.chunk_lock);
	m.sftp_buf_sz = DEFAULT_SFTP_BUF_SZ;
	m.io_buf_sz = DEFAULT_IO_BUF_SZ;
	m.nr_ahead = DEFAULT_NR_AHEAD;

	m.nr_threads = (int)(nr_cpus() / 2);
	m.nr_threads = m.nr_threads == 0 ? 1 : m.nr_threads;

	while ((ch = getopt(argc, argv, "n:m:s:S:b:B:a:vqDl:p:i:c:CHdh")) != -1) {
		switch (ch) {
		case 'n':
			m.nr_threads = atoi(optarg);
			if (m.nr_threads < 1) {
				pr_err("invalid number of connections: %s\n", optarg);
				return 1;
			}
			break;
		case 'm':
			coremask = optarg;
			break;
		case 's':
			min_chunk_sz = atoi(optarg);
			if (min_chunk_sz < getpagesize()) {
				pr_err("min chunk size must be "
				       "larger than or equal to %d: %s\n",
				       getpagesize(), optarg);
				return 1;
			}
			if (min_chunk_sz % getpagesize() != 0) {
				pr_err("min chunk size must be "
				       "multiple of page size %d: %s\n",
				       getpagesize(), optarg);
				return -1;
			}
			break;
		case 'S':
			max_chunk_sz = atoi(optarg);
			if (max_chunk_sz < getpagesize()) {
				pr_err("max chunk size must be "
				       "larger than or equal to %d: %s\n",
				       getpagesize(), optarg);
				return 1;
			}
			if (max_chunk_sz % getpagesize() != 0) {
				pr_err("max chunk size must be "
				       "multiple of page size %d: %s\n",
				       getpagesize(), optarg);
				return -1;
			}
			break;
		case 'b':
			m.sftp_buf_sz = atoi(optarg);
			if (m.sftp_buf_sz < 1) {
				pr_err("invalid buffer size: %s\n", optarg);
				return -1;
			}
			break;
		case 'B':
			m.io_buf_sz = atoi(optarg);
			if (m.io_buf_sz < 1) {
				pr_err("invalid buffer size: %s\n", optarg);
				return -1;
			}
			break;
		case 'a':
			m.nr_ahead = atoi(optarg);
			if (m.nr_ahead < 1) {
				pr_err("invalid number of ahead: %s\n", optarg);
				return -1;
			}
			break;
		case 'v':
			verbose++;
			break;
		case 'q':
			verbose = -1;
			break;
		case 'D':
			dryrun = true;
			break;
		case 'l':
			opts.login_name = optarg;
			break;
		case 'p':
			opts.port = optarg;
			break;
		case 'i':
			opts.identity = optarg;
			break;
		case 'c':
			opts.cipher = optarg;
			break;
		case 'C':
			opts.compress++;
			break;
		case 'H':
			opts.no_hostkey_check = true;
			break;
		case 'd':
			opts.debuglevel++;
			break;
		case 'h':
			usage(true);
			return 0;
		default:
			usage(false);
			return 1;
		}
	}

	pprint_set_level(verbose);

	if (argc - optind < 2) {
		/* mscp needs at lease 2 (src and target) argument */
		usage(false);
		return 1;
	}
	m.target = argv[argc - 1];

	if (max_chunk_sz > 0 && min_chunk_sz > max_chunk_sz) {
		pr_err("smaller max chunk size than min chunk size: %d < %d\n",
		       max_chunk_sz, min_chunk_sz);
		return 1;
	}

	/* expand usable cores from coremask */
	if (coremask) {
		if (expand_coremask(coremask, &cores, &nr_cores) < 0)
			return -1;
		pprint(2, "cpu cores:");
		for (n = 0; n < nr_cores; n++)
			pprint(2, " %d", cores[n]);
		pprint(2, "\n");
	}

	/* create control session */
	m.host = find_hostname(optind, argc, argv);
	if (!m.host) {
		pr_err("no remote host given\n");
		return 1;
	}
	pprint3("connecting to %s for checking destinations...\n", m.host);
	m.ctrl = ssh_init_sftp_session(m.host, &opts);
	if (!m.ctrl)
		return 1;
	m.opts = &opts; /* save ssh-able ssh_opts */


	/* fill file list */
	ret = file_fill(m.ctrl, &m.file_list, &argv[optind], argc - optind - 1,
			m.target);
	if (ret < 0)
		goto out;

#ifdef DEBUG
	file_dump(&m.file_list);
#endif

	/* fill chunk list */
	ret = chunk_fill(&m.file_list, &m.chunk_list,
			 m.nr_threads, min_chunk_sz, max_chunk_sz);
	if (ret < 0)
		goto out;

#ifdef DEBUG
	chunk_dump(&m.chunk_list);
#endif

	if (dryrun)
		return 0;

	/* prepare thread instances */
	if ((n = list_count(&m.chunk_list)) < m.nr_threads) {
		pprint3("we have only %d chunk(s). set NR_CONNECTIONS to %d\n", n, n);
		m.nr_threads = n;
	}

	m.threads = calloc(m.nr_threads, sizeof(struct mscp_thread));
	memset(m.threads, 0, m.nr_threads * sizeof(struct mscp_thread));
	for (n = 0; n < m.nr_threads; n++) {
		struct mscp_thread *t = &m.threads[n];
		t->finished = false;
		if (!coremask)
			t->cpu = -1;
		else
			t->cpu = cores[n % nr_cores];

		pprint3("connecting to %s for a copy thread...\n", m.host);
		t->sftp = ssh_init_sftp_session(m.host, m.opts);
		if (!t->sftp) {
			ret = 1;
			goto join_out;
		}
	}

	/* init mscp stat for printing progress bar */
	if (mscp_stat_init() < 0) {
		stop_copy_threads(0);
		ret = 1;
		goto join_out;
	}

	/* register SIGINT to stop threads */
	if (signal(SIGINT, stop_copy_threads) == SIG_ERR) {
		pr_err("cannot set signal: %s\n", strerrno());
		ret = 1;
		goto out;
	}

	/* spawn copy threads */
	for (n = 0; n < m.nr_threads; n++) {
		struct mscp_thread *t = &m.threads[n];
		ret = pthread_create(&t->tid, NULL, mscp_copy_thread, t);
		if (ret < 0) {
			pr_err("pthread_create error: %d\n", ret);
			stop_copy_threads(0);
			ret = 1;
			goto join_out;
		}
	}

join_out:
	/* waiting for threads join... */
	for (n = 0; n < m.nr_threads; n++) {
		if (m.threads[n].tid) {
			pthread_join(m.threads[n].tid, NULL);
			if (m.threads[n].ret < 0)
				ret = m.threads[n].ret;
		}
	}

	/* print final result */
	mscp_stat_final();

out:
	if (m.ctrl)
		ssh_sftp_close(m.ctrl);

	return ret;
}

void mscp_copy_thread_cleanup(void *arg)
{
	struct mscp_thread *t = arg;
	if (t->sftp)
		ssh_sftp_close(t->sftp);
	t->finished = true;
	__sync_synchronize();
}

void *mscp_copy_thread(void *arg)
{
	struct mscp_thread *t = arg;
	sftp_session sftp = t->sftp;
	struct chunk *c;

	if (t->cpu > -1) {
		if (set_thread_affinity(pthread_self(), t->cpu) < 0)
			return NULL;
	}

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	pthread_cleanup_push(mscp_copy_thread_cleanup, t);

	while (1) {
		lock_acquire(&m.chunk_lock);
		c = chunk_acquire(&m.chunk_list);
		lock_release(&m.chunk_lock);

		if (!c)
			break; /* no more chunks */

		if ((t->ret = chunk_prepare(c, sftp)) < 0)
			break;

		if ((t->ret = chunk_copy(c, sftp, m.sftp_buf_sz, m.io_buf_sz,
					 m.nr_ahead, &t->done)) < 0)
			break;
	}

	pthread_cleanup_pop(1);

	if (t->ret < 0)
		pr_err("copy failed: chunk %s 0x%010lx-0x%010lx\n",
		       c->f->src_path, c->off, c->off + c->len);

	return NULL;
}


/* progress bar-related functions */

static double calculate_timedelta(struct timeval *b, struct timeval *a)
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

	pprint1("%s%s", buf, suffix);
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

	snprintf(suffix, sizeof(suffix), "%lu%s/%lu%s %6.1f%s  %s",
		 done_round, byte_units[byte_du], total_round, byte_units[byte_tu],
		 bps, bps_units[bps_u], calculate_eta(total - done, done - last, b, a));

	print_progress_bar(percent, suffix);
}


struct mscp_stat {
	struct timeval start, before, after;
	size_t total;
	size_t last;
	size_t done;
} s;

void mscp_stat_handler(int signum)
{
	int n;

	for (s.done = 0, n = 0; n < m.nr_threads; n++)
		s.done += m.threads[n].done;

	gettimeofday(&s.after, NULL);
	alarm(1);

	print_progress(&s.before, &s.after, s.total, s.last, s.done);
	s.before = s.after;
	s.last = s.done;
}

int mscp_stat_init()
{
	struct file *f;

	memset(&s, 0, sizeof(s));
	list_for_each_entry(f, &m.file_list, list) {
		s.total += f->size;
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

void mscp_stat_final()
{
	alarm(0);
	mscp_stat_handler(0);
	alarm(0);
}
