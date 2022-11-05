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

struct mscp {
	char                    *host;  /* remote host (and username) */
	struct ssh_opts         *opts;  /* ssh parameters */
	sftp_session            ctrl;   /* control sftp session */

	struct list_head        file_list;
	struct list_head        chunk_list;     /* stack of chunks */
	lock                    chunk_lock;  /* lock for chunk list */

	char    *target;

	int     sftp_buf_sz, io_buf_sz;

	struct timeval start;   /* timestamp of starting copy */
};

struct mscp_thread {
	struct mscp     *mscp;
	sftp_session    sftp;

	pthread_t       tid;
	size_t          done;           /* copied bytes */
	bool            finished;
	int		ret;
};

void *mscp_copy_thread(void *arg);
void *mscp_monitor_thread(void *arg);

pthread_t mtid;
struct mscp_thread *threads;
int nr_threads;

void stop_copy_threads(int sig)
{
	int n;

	pr("stopping...\n");
	for (n = 0; n < nr_threads; n++) {
		pthread_cancel(threads[n].tid);
	}
}

int list_count(struct list_head *head)
{
	int n = 0;
	struct list_head *p;

	list_for_each(p, head) n++;
	return n;
}

void usage(bool print_help) {
	printf("mscp v" VERSION ": copy files over multiple ssh connections\n"
	       "\n"
	       "Usage: mscp [vqDCHdh] [-n nr_conns]\n"
	       "            [-s min_chunk_sz] [-S max_chunk_sz]\n"
	       "            [-b sftp_buf_sz] [-B io_buf_sz]\n"
	       "            [-l login_name] [-p port] [-i identity_file]\n"
	       "            [-c cipher_spec] source ... target\n"
	       "\n");

	if (!print_help)
		return;

	printf("    -n NR_CONNECTIONS  number of connections (default: half of # of cpu cores)\n"
	       "    -s MIN_CHUNK_SIZE  min chunk size (default: 64MB)\n"
	       "    -S MAX_CHUNK_SIZE  max chunk size (default: filesize / nr_conn)\n"
	       "    -b SFTP_BUF_SIZE   buf size for sftp_read/write (default 131072B)\n"
	       "    -B IO_BUF_SIZE     buf size for read/write (default 131072B)\n"
	       "                       Note that this value is derived from\n"
	       "                       qemu/block/ssh.c. need investigation...\n"
	       "    -v                 increment verbose output level\n"
	       "    -q                 disable output\n"
	       "    -D                 dry run\n"
	       "\n"
	       "    -l LOGIN_NAME      login name\n"
	       "    -p PORT            port number\n"
	       "    -i IDENTITY        identity file for publickey authentication\n"
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

int main(int argc, char **argv)
{
	struct mscp m;
	struct ssh_opts opts;
	int min_chunk_sz = DEFAULT_MIN_CHUNK_SZ;
	int max_chunk_sz = 0;
	int verbose = 1;
	bool dryrun = false;
	int ret = 0, n;
	char ch;

	memset(&opts, 0, sizeof(opts));
	memset(&m, 0, sizeof(m));
	INIT_LIST_HEAD(&m.file_list);
	INIT_LIST_HEAD(&m.chunk_list);
	lock_init(&m.chunk_lock);
	m.sftp_buf_sz = DEFAULT_SFTP_BUF_SZ;
	m.io_buf_sz = DEFAULT_IO_BUF_SZ;

	nr_threads = (int)(nr_cpus() / 2);
	nr_threads = nr_threads == 0 ? 1 : nr_threads;

	while ((ch = getopt(argc, argv, "n:s:S:b:B:vqDl:p:i:c:CHdh")) != -1) {
		switch (ch) {
		case 'n':
			nr_threads = atoi(optarg);
			if (nr_threads < 1) {
				pr_err("invalid number of connections: %s\n", optarg);
				return 1;
			}
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

	if (max_chunk_sz > 0 && min_chunk_sz > max_chunk_sz) {
		pr_err("smaller max chunk size than min chunk size: %d < %d\n",
		       max_chunk_sz, min_chunk_sz);
		return 1;
	}

	if (argc - optind < 2) {
		/* mscp needs at lease 2 (src and target) argument */
		usage(false);
		return 1;
	}

	m.target = argv[argc - 1];

	/* create control session */
	m.host = find_hostname(optind, argc, argv);
	if (!m.host) {
		pr_err("no remote host given\n");
		return 1;
	}
	pprint3("connecting to %s for checking destinations...\n", m.host);
	m.ctrl = ssh_make_sftp_session(m.host, &opts);
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
			 nr_threads, min_chunk_sz, max_chunk_sz);
	if (ret < 0)
		goto out;

#ifdef DEBUG
	chunk_dump(&m.chunk_list);
#endif

	if (dryrun)
		return 0;

	/* register SIGINT to stop thrads */
	if (signal(SIGINT, stop_copy_threads) == SIG_ERR) {
		pr_err("cannot set signal: %s\n", strerrno());
		ret = 1;
		goto out;
	}

	/* prepare thread instances */
	if ((n = list_count(&m.chunk_list)) < nr_threads) {
		pprint3("we have only %d chunk(s). set nr_conns to %d\n", n, n);
		nr_threads = n;
	}

	threads = calloc(nr_threads, sizeof(struct mscp_thread));
	memset(threads, 0, nr_threads * sizeof(struct mscp_thread));
	for (n = 0; n < nr_threads; n++) {
		struct mscp_thread *t = &threads[n];
		t->mscp = &m;
		t->finished = false;
		pprint3("connecting to %s for a copy thread...\n", m.host);
		t->sftp = ssh_make_sftp_session(m.host, m.opts);
		if (!t->sftp) {
			ret = 1;
			goto join_out;
		}
	}

	/* spawn count thread */
	ret = pthread_create(&mtid, NULL, mscp_monitor_thread, &m);
	if (ret < 0) {
		pr_err("pthread_create error: %d\n", ret);
		stop_copy_threads(0);
		ret = 1;
		goto join_out;
	}

	/* save start time */
	gettimeofday(&m.start, NULL);

	/* spawn threads */
	for (n = 0; n < nr_threads; n++) {
		struct mscp_thread *t = &threads[n];
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
	for (n = 0; n < nr_threads; n++)
		if (threads[n].tid) {
			pthread_join(threads[n].tid, NULL);
			if (threads[n].ret < 0)
				ret = threads[n].ret;
		}

	if (mtid != 0) {
		pthread_cancel(mtid);
		pthread_join(mtid, NULL);
	}

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
}

void *mscp_copy_thread(void *arg)
{
	struct mscp_thread *t = arg;
	struct mscp *m = t->mscp;
	sftp_session sftp = t->sftp;
	struct chunk *c;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	pthread_cleanup_push(mscp_copy_thread_cleanup, t);

	while (1) {
		lock_acquire(&m->chunk_lock);
		c = chunk_acquire(&m->chunk_list);
		lock_release(&m->chunk_lock);

		if (!c)
			break; /* no more chunks */

		if ((t->ret = chunk_prepare(c, sftp)) < 0)
			break;

		if ((t->ret = chunk_copy(c, sftp,
					 m->sftp_buf_sz, m->io_buf_sz, &t->done)) < 0)
			break;
	}

	pthread_cleanup_pop(1);

	return NULL;
}

static double calculate_bps(size_t diff, struct timeval *b, struct timeval *a)
{
	double sec, usec;

	if (a->tv_usec < b->tv_usec) {
		a->tv_usec += 1000000;
		a->tv_sec--;
	}

	sec = a->tv_sec - b->tv_sec;
	usec = a->tv_usec - b->tv_usec;
	sec += usec / 1000000;

	return (double)diff / sec;
}

static void print_progress_bar(double percent, char *suffix)
{
	int n, thresh, bar_width;
	struct winsize ws;
	char buf[128];

	/*
	 * [=======>   ] XX.X% SUFFIX
	 */

	buf[0] = '\0';

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0)
		return; /* XXX */
	bar_width = min(sizeof(buf), ws.ws_col) - strlen(suffix) - 8;

	if (bar_width > 8) {
		memset(buf, 0, sizeof(buf));
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

static void print_progress(struct timeval *start, struct timeval *end,
			   size_t total, size_t last, size_t done)
{
	char *bps_units[] = { "B/s", "KB/s", "MB/s", "GB/s" };
	char *byte_units[] = { "B", "KB", "MB", "GB", "TB", "PB" };
	char suffix[128];
	int bps_u, byte_tu, byte_du;
	size_t total_round;
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

	bps = calculate_bps(done - last, start, end);
	for (bps_u = 0; bps > 1000 && bps_u < array_size(bps_units); bps_u++)
		bps /= 1000;

	percent = floor(((double)(done) / (double)total) * 100);
	for (byte_du = 0; done > 1000 && byte_du < array_size(byte_units) - 1; byte_du++)
		done /= 1024;

	snprintf(suffix, sizeof(suffix), "%lu%s/%lu%s %.2f%s ",
		 done, byte_units[byte_du], total_round, byte_units[byte_tu],
		 bps, bps_units[bps_u]);

	print_progress_bar(percent, suffix);
}

void mscp_monitor_thread_cleanup(void *arg)
{
	struct mscp *m = arg;
	struct timeval end;
	struct file *f;
	size_t total, done;
	int n;

	total = done = 0;

	gettimeofday(&end, NULL);

	/* get total byte to be transferred */
	list_for_each_entry(f, &m->file_list, list) {
		total += f->size;
	}

	/* get total byte transferred */
	for (n = 0; n < nr_threads; n++) {
		done += threads[n].done;
	}

	print_progress(&m->start, &end, total, 0, done);
	fputs("\n", stdout); /* the final ouput. we need \n */
}

void *mscp_monitor_thread(void *arg)
{
	struct mscp *m = arg;
	struct timeval a, b;
	struct file *f;
	bool all_done;
	size_t total, done, last;
	int n;

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	pthread_cleanup_push(mscp_monitor_thread_cleanup, m);

	/* get total byte to be transferred */
	total = 0;
	list_for_each_entry(f, &m->file_list, list) {
		total += f->size;
	}

	while (1) {
		all_done = true;
		last = done = 0;

		for (n = 0; n < nr_threads; n++) {
			last += threads[n].done;
		}
		gettimeofday(&b, NULL);

		usleep(500000);

		for (n = 0; n < nr_threads; n++) {
			done += threads[n].done;;
			if (!threads[n].finished)
				all_done = false;
		}
		gettimeofday(&a, NULL);

		print_progress(&b, &a, total, last, done);

		if (all_done || total == done)
			break;
	}

	pthread_cleanup_pop(1);

	return NULL;
}
