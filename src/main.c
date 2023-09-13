#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <pthread.h>

#include <mscp.h>
#include <mscp_version.h>
#include <util.h>


void usage(bool print_help) {
	printf("mscp " MSCP_BUILD_VERSION ": copy files over multiple ssh connections\n"
	       "\n"
	       "Usage: mscp [vqDHdNh] [-n nr_conns] [-m coremask] [-u max_startups]\n"
	       "            [-s min_chunk_sz] [-S max_chunk_sz] [-a nr_ahead] [-b buf_sz]\n"
	       "            [-l login_name] [-p port] [-F ssh_config] [-i identity_file]\n"
	       "            [-c cipher_spec] [-M hmac_spec] [-C compress] [-g congestion]\n"
	       "            source ... target\n"
	       "\n");

	if (!print_help)
		return;

	printf("    -n NR_CONNECTIONS  number of connections "
	       "(default: floor(log(cores)*2)+1)\n"
	       "    -m COREMASK        hex value to specify cores where threads pinned\n"
	       "    -u MAX_STARTUPS    number of concurrent outgoing connections "
	       "(default: 8)\n"
	       "    -s MIN_CHUNK_SIZE  min chunk size (default: 64MB)\n"
	       "    -S MAX_CHUNK_SIZE  max chunk size (default: filesize/nr_conn)\n"
	       "\n"
	       "    -a NR_AHEAD        number of inflight SFTP commands (default: 32)\n"
	       "    -b BUF_SZ          buffer size for i/o and transfer\n"
	       "\n"
	       "    -v                 increment verbose output level\n"
	       "    -q                 disable output\n"
	       "    -D                 dry run. check copy destinations with -vvv\n"
	       "    -r                 no effect\n"
	       "\n"
	       "    -l LOGIN_NAME      login name\n"
	       "    -p PORT            port number\n"
	       "    -F CONFIG          path to user ssh config (default ~/.ssh/config)\n"
	       "    -i IDENTITY        identity file for public key authentication\n"
	       "    -c CIPHER          cipher spec\n"
	       "    -M HMAC            hmac spec\n"
	       "    -C COMPRESS        enable compression: "
	       "yes, no, zlib, zlib@openssh.com\n"
	       "    -g CONGESTION      specify TCP congestion control algorithm\n"
	       "    -H                 disable hostkey check\n"
	       "    -d                 increment ssh debug output level\n"
	       "    -N                 enable Nagle's algorithm (default disabled)\n"
	       "    -h                 print this help\n"
	       "\n");
}

char *split_remote_and_path(const char *string, char **remote, char **path)
{
	char *s, *p;

	/* split user@host:path into user@host, and path.
	 * return value is strdup()ed memory (for free()).
	 */

	if (!(s = strdup(string))) {
		fprintf(stderr, "strdup: %s\n", strerror(errno));
		return NULL;
	}

	if ((p = strchr(s, ':'))) {
		if (p == s || ((p > s) && *(p - 1) == '\\')) {
			/* first byte is colon, or escaped colon. no user@host here  */
			goto no_remote;
		} else {
			/* we found ':', so this is remote:path notation. split it */
			*p = '\0';
			*remote = s;
			*path = p + 1;
			return s;
		}
	}

no_remote:
	*remote = NULL;
	*path = s;
	return s;
}

struct target {
	char *remote;
	char *path;
};

struct target *validate_targets(char **arg, int len)
{
	/* arg is array of source ... destination.
	 * There are two cases:
	 *
	 * 1. remote:path remote:path ... path, remote to local copy
	 * 2. path path ... remote:path, local to remote copy.
	 *
	 * This function split (remote:)path args into struct target,
	 * and validate all remotes are identical (mscp does not support
	 * remote to remote copy).
	 */

	struct target *t;
	char *r;
	int n;

	if ((t = calloc(len, sizeof(struct target))) == NULL) {
		fprintf(stderr, "calloc: %s\n", strerror(errno));
		return NULL;
	}
	memset(t, 0, len * sizeof(struct target));

	/* split remote:path into remote and path */
	for (n = 0; n < len; n++) {
		if (split_remote_and_path(arg[n], &t[n].remote, &t[n].path) == NULL)
			goto free_target_out;
	}

	/* check all remote are identical. t[len - 1] is destination,
	 * so we need to check t[0] to t[len - 2] having the identical
	 * remote */
	r = t[0].remote;
	for (n = 1; n < len - 1; n++) {
		if (!r && t[n].remote) {
			goto invalid_remotes;
		}
		if (r) {
			if (!t[n].remote ||
			    strlen(r) != strlen(t[n].remote) ||
			    strcmp(r, t[n].remote) != 0)
				goto invalid_remotes;
		}
	}

	/* check inconsistent remote position in args */
	if (t[0].remote == NULL && t[len - 1].remote == NULL) {
		fprintf(stderr, "no remote host given\n");
		goto free_split_out;
	}

	if (t[0].remote != NULL && t[len - 1].remote != NULL) {
		fprintf(stderr, "no local path given\n");
		goto free_split_out;
	}

	return t;

invalid_remotes:
	fprintf(stderr, "specified remote host invalid\n");

free_split_out:
	for (n = 0; n < len; n++)
		t[n].remote ? free(t[n].remote) : free(t[n].path);

free_target_out:
	free(t);
	return NULL;
}

struct mscp *m = NULL;
int msg_fd = 0;
pthread_t tid_stat = 0;

void sigint_handler(int sig)
{
	mscp_stop(m);
}

void *print_stat_thread(void *arg);

void print_cli(const char *fmt, ...)
{
        va_list va;
	va_start(va, fmt);
	vfprintf(stdout, fmt, va);
	fflush(stdout);
	va_end(va);
}

int main(int argc, char **argv)
{
	struct mscp_ssh_opts s;
	struct mscp_opts o;
	struct target *t;
	int pipe_fd[2];
	int ch, n, i, ret;
	int direction = 0;
	char *remote;
	bool dryrun = false;

	memset(&s, 0, sizeof(s));
	memset(&o, 0, sizeof(o));
	o.severity = MSCP_SEVERITY_WARN;

	while ((ch = getopt(argc, argv,
			    "n:m:u:s:S:a:b:vqDrl:p:i:F:c:M:C:g:HdNh")) != -1) {
		switch (ch) {
		case 'n':
			o.nr_threads = atoi(optarg);
			if (o.nr_threads < 1) {
				fprintf(stderr, "invalid number of connections: %s\n",
					optarg);
				return 1;
			}
			break;
		case 'm':
			strncpy(o.coremask, optarg, sizeof(o.coremask));
			break;
		case 'u':
			o.max_startups = atoi(optarg);
			break;
		case 's':
			o.min_chunk_sz = atoi(optarg);
			break;
		case 'S':
			o.max_chunk_sz = atoi(optarg);
			break;
		case 'a':
			o.nr_ahead = atoi(optarg);
			break;
		case 'b':
			o.buf_sz = atoi(optarg);
			break;
		case 'v':
			o.severity++;
			break;
		case 'q':
			o.severity = MSCP_SEVERITY_NONE;
			break;
		case 'D':
			dryrun = true;
			break;
		case 'r':
			/* for compatibility with scp */
			break;
		case 'l':
			if (strlen(optarg) > MSCP_SSH_MAX_LOGIN_NAME - 1) {
				fprintf(stderr, "long login name: %s\n", optarg);
				return -1;
			}
			strncpy(s.login_name, optarg, MSCP_SSH_MAX_LOGIN_NAME - 1);
			break;
		case 'p':
			if (strlen(optarg) > MSCP_SSH_MAX_PORT_STR - 1) {
				fprintf(stderr, "long port string: %s\n", optarg);
				return -1;
			}
			strncpy(s.port, optarg, MSCP_SSH_MAX_PORT_STR);
			break;
		case 'F':
			strncpy(s.config, optarg, PATH_MAX - 1);
			break;
		case 'i':
			if (strlen(optarg) > MSCP_SSH_MAX_IDENTITY_PATH - 1) {
				fprintf(stderr, "long identity path: %s\n", optarg);
				return -1;
			}
			strncpy(s.identity, optarg, MSCP_SSH_MAX_IDENTITY_PATH);
			break;
		case 'c':
			if (strlen(optarg) > MSCP_SSH_MAX_CIPHER_STR - 1) {
				fprintf(stderr, "long cipher string: %s\n", optarg);
				return -1;
			}
			strncpy(s.cipher, optarg, MSCP_SSH_MAX_CIPHER_STR);
			break;
		case 'M':
			if (strlen(optarg) > MSCP_SSH_MAX_HMAC_STR - 1) {
				fprintf(stderr, "long hmac string: %s\n", optarg);
				return -1;
			}
			strncpy(s.hmac, optarg, MSCP_SSH_MAX_HMAC_STR);
			break;
		case 'C':
			if (strlen(optarg) > MSCP_SSH_MAX_COMP_STR - 1) {
				fprintf(stderr, "long compress string: %s\n", optarg);
				return -1;
			}
			strncpy(s.compress, optarg, MSCP_SSH_MAX_COMP_STR);
			break;
		case 'g':
			if (strlen(optarg) > MSCP_SSH_MAX_CCALGO_STR - 1) {
				fprintf(stderr, "long ccalgo string: %s\n", optarg);
				return -1;
			}
			strncpy(s.ccalgo, optarg, MSCP_SSH_MAX_CCALGO_STR);
			break;
		case 'H':
			s.no_hostkey_check = true;
			break;
		case 'd':
			s.debug_level++;
			break;
		case 'N':
			s.enable_nagle = true;
			break;
		case 'h':
			usage(true);
			return 0;
		default:
			usage(false);
			return 1;
		}
	}

	if (argc - optind < 2) {
		/* mscp needs at lease 2 (src and target) argument */
		usage(false);
		return 1;
	}
	i = argc - optind;

	if ((t = validate_targets(argv + optind, i)) == NULL)
		return -1;

	if (t[0].remote) {
		/* copy remote to local */
		direction = MSCP_DIRECTION_R2L;
		remote = t[0].remote;
	} else {
		/* copy local to remote */
		direction = MSCP_DIRECTION_L2R;
		remote = t[i - 1].remote;
	}

	if (!dryrun) {
		if (pipe(pipe_fd) < 0) {
			fprintf(stderr, "pipe: %s\n", strerror(errno));
			return -1;
		}
		msg_fd = pipe_fd[0];
		o.msg_fd = pipe_fd[1];
	}

	if ((m = mscp_init(remote, direction, &o, &s)) == NULL) {
		fprintf(stderr, "mscp_init: %s\n", mscp_get_error());
		return -1;
	}

	if (mscp_connect(m) < 0) {
		fprintf(stderr, "mscp_connect: %s\n", mscp_get_error());
		return -1;
	}

	for (n = 0; n < i - 1; n++) {
		if (mscp_add_src_path(m, t[n].path) < 0) {
			fprintf(stderr, "mscp_add_src_path: %s\n", mscp_get_error());
			return -1;
		}
        }

	if (mscp_set_dst_path(m, t[i - 1].path) < 0) {
		fprintf(stderr, "mscp_set_dst_path: %s\n", mscp_get_error());
		return -1;
	}

	if (mscp_scan(m) < 0) {
		fprintf(stderr, "mscp_scan: %s\n", mscp_get_error());
		return -1;
	}

	if (dryrun) {
		ret = mscp_scan_join(m);
		goto out;
	}

	if (pthread_create(&tid_stat, NULL, print_stat_thread, NULL) < 0) {
		fprintf(stderr, "pthread_create: %s\n", strerror(errno));
		return -1;
	}

	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		fprintf(stderr, "signal: %s\n", strerror(errno));
		return -1;
	}

	ret = mscp_start(m);
	if (ret < 0)
		fprintf(stderr, "mscp_start: %s\n", mscp_get_error());

	ret = mscp_join(m);
	if (ret != 0)
		fprintf(stderr, "mscp_join: %s\n", mscp_get_error());

	pthread_cancel(tid_stat);
	pthread_join(tid_stat, NULL);

out:
	mscp_cleanup(m);
	mscp_free(m);

	return ret;
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


double calculate_bps(size_t diff, struct timeval *b, struct timeval *a)
{
        return (double)diff / calculate_timedelta(b, a);
}


char *calculate_eta(size_t remain, size_t diff, struct timeval *b, struct timeval *a,
		    bool final)
{
        static char buf[16];

#define bps_window_size 16
	static double bps_window[bps_window_size];
	static size_t sum, idx, count;
        double elapsed = calculate_timedelta(b, a);
	double bps = diff / elapsed;
	double avg, eta;

	/* early return when diff == 0 (stalled) or final output */
        if (diff == 0) {
                snprintf(buf, sizeof(buf), "--:-- ETA");
		return buf;
	}
	if (final) {
		snprintf(buf, sizeof(buf), "%02d:%02d    ",
			 (int)(floor(elapsed / 60)), (int)round(elapsed) % 60);
		return buf;
	}

	/* drop the old bps value and add the recent one */
	sum -= bps_window[idx];
	bps_window[idx] = bps;
	sum += bps_window[idx];
	idx = (idx + 1) % bps_window_size;
	count++;

	/* calcuate ETA from avg of recent bps values */
	avg = sum / min(count, bps_window_size);
	eta = remain / avg;
	snprintf(buf, sizeof(buf), "%02d:%02d ETA",
		 (int)floor(eta / 60), (int)round(eta) % 60);

        return buf;
}

void print_progress_bar(double percent, char *suffix)
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

	print_cli("\r\033[K" "%s%s", buf, suffix);
}

void print_progress(struct timeval *b, struct timeval *a,
		    size_t total, size_t last, size_t done, bool final)
{
        char *bps_units[] = { "B/s ", "KB/s", "MB/s", "GB/s" };
        char *byte_units[] = { "B ", "KB", "MB", "GB", "TB", "PB" };
        char suffix[128];
        int bps_u, byte_tu, byte_du;
        double total_round, done_round;
        int percent;
        double bps;

#define array_size(a) (sizeof(a) / sizeof(a[0]))

        if (total <= 0) {
		print_cli("\r\033[K" "total 0 byte transferred");
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
        for (byte_du = 0; done_round > 1024 && byte_du < array_size(byte_units) - 1;
             byte_du++)
                done_round /= 1024;

        snprintf(suffix, sizeof(suffix), "%4.1lf%s/%.1lf%s %6.1f%s  %s",
                 done_round, byte_units[byte_du], total_round, byte_units[byte_tu],
                 bps, bps_units[bps_u],
		 calculate_eta(total - done, done - last, b, a, final));

        print_progress_bar(percent, suffix);
}


struct xfer_stat {
        struct timeval start, before, after;
        size_t total;
        size_t last;
        size_t done;
};
struct xfer_stat x;

void print_stat(bool final)
{
	struct pollfd pfd = { .fd = msg_fd, .events = POLLIN };
	struct mscp_stats s;
	char buf[8192];
	int timeout;

	if (poll(&pfd, 1, !final ? 100 : 0) < 0) {
		fprintf(stderr, "poll: %s\n", strerror(errno));
		return;
	}

	if (pfd.revents & POLLIN) {
		memset(buf, 0, sizeof(buf));
		if (read(msg_fd, buf, sizeof(buf)) < 0) {
			fprintf(stderr, "read: %s\n", strerror(errno));
			return;
		}
		print_cli("\r\033[K" "%s", buf);
	}

	gettimeofday(&x.after, NULL);
	if (calculate_timedelta(&x.before, &x.after) > 1 || final) {
		mscp_get_stats(m, &s);
		x.total = s.total;
		x.done = s.done;
		print_progress(!final ? &x.before : &x.start, &x.after,
			       x.total, !final ? x.last : 0, x.done, final);
		x.before = x.after;
		x.last = x.done;
	}
}

void print_stat_thread_cleanup(void *arg)
{
	print_stat(true);
	print_cli("\n"); /* final output */
}

void *print_stat_thread(void *arg)
{
	struct pollfd pfd = { .fd = msg_fd, .events = POLLIN };
	struct mscp_stats s;
	char buf[8192];

	memset(&x, 0, sizeof(x));
        gettimeofday(&x.start, NULL);
        x.before = x.start;

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        pthread_cleanup_push(print_stat_thread_cleanup, NULL);

	while (true) {
		print_stat(false);
	}

	pthread_cleanup_pop(1);
	return NULL;
}
