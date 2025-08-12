/* SPDX-License-Identifier: GPL-3.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>

#include <mscp.h>
#include <minmax.h>
#include <strerrno.h>
#include <print.h>

#include <config.h>

void usage(bool print_help)
{
	printf("mscp " MSCP_BUILD_VERSION ": copy files over multiple SSH connections\n"
	       "\n"
	       "Usage: mscp [-46vqDpdNh] [-n nr_conns] [-m coremask] [-u max_startups]\n"
	       "            [-I interval] [-W checkpoint] [-R checkpoint]\n"
	       "            [-s min_chunk_sz] [-S max_chunk_sz] [-a nr_ahead]\n"
	       "            [-b buf_sz] [-L limit_bitrate]\n"
	       "            [-l login_name] [-P port] [-F ssh_config] [-o ssh_option]\n"
	       "            [-i identity_file] [-J destination] [-c cipher_spec] [-M hmac_spec]\n"
	       "            [-C compress] [-g congestion]\n"
	       "            source ... target\n"
	       "\n");

	if (!print_help)
		return;

	printf("    -n NR_CONNECTIONS  number of connections "
	       "(default: floor(log(cores)*2)+1)\n"
	       "    -m COREMASK        hex value to specify cores where threads pinned\n"
	       "    -u MAX_STARTUPS    number of concurrent unauthed SSH attempts "
	       "(default: 8)\n"
	       "    -I INTERVAL        interval between SSH connection attempts (default: 0)\n"
	       "    -W CHECKPOINT      write states to the checkpoint if transfer fails\n"
	       "    -R CHECKPOINT      resume transferring from the checkpoint\n"
	       "\n"
	       "    -s MIN_CHUNK_SIZE  min chunk size (default: 16M bytes)\n"
	       "    -S MAX_CHUNK_SIZE  max chunk size (default: filesize/nr_conn/4)\n"
	       "    -a NR_AHEAD        number of inflight SFTP commands (default: 32)\n"
	       "    -b BUF_SZ          buffer size for i/o and transfer\n"
	       "    -L LIMIT_BITRATE   Limit the bitrate, n[KMG] (default: 0, no limit)\n"
	       "\n"
	       "    -4                 use IPv4\n"
	       "    -6                 use IPv6\n"
	       "    -v                 increment verbose output level\n"
	       "    -q                 disable output\n"
	       "    -D                 dry run. check copy destinations with -vvv\n"
	       "    -r                 no effect\n"
	       "\n"
	       "    -l LOGIN_NAME      login name\n"
	       "    -P PORT            port number\n"
	       "    -F SSH_CONFIG      path to user ssh config (default ~/.ssh/config)\n"
	       "    -o SSH_OPTION      ssh_config option\n"
	       "    -i IDENTITY        identity file for public key authentication\n"
	       "    -J DESTINATION     ProxyJump destination\n"
	       "    -c CIPHER          cipher spec\n"
	       "    -M HMAC            hmac spec\n"
	       "    -C COMPRESS        enable compression: "
	       "yes, no, zlib, zlib@openssh.com\n"
	       "    -g CONGESTION      specify TCP congestion control algorithm\n"
	       "    -p                 preserve timestamps of files\n"
	       "    -d                 increment ssh debug output level\n"
	       "    -N                 enable Nagle's algorithm (default disabled)\n"
	       "    -h                 print this help\n"
	       "\n");

	const char **ciphers = mscp_ssh_ciphers();
	const char **hmacs = mscp_ssh_hmacs();
	int n;

	printf("Available ciphers: ");
	for (n = 0; ciphers[n] != NULL; n++) {
		printf("%s", ciphers[n]);
		if (ciphers[n + 1])
			printf(", ");
	}
	printf("\n\n");

	printf("Available hmacs: ");
	for (n = 0; hmacs[n] != NULL; n++) {
		printf("%s", hmacs[n]);
		if (hmacs[n + 1])
			printf(", ");
	}
	printf("\n\n");
}

char *strip_brackets(char *s)
{
	if (s[0] == '[' && s[strlen(s) - 1] == ']') {
		s[strlen(s) - 1] = '\0';
		return s + 1;
	}
	return s;
}

char *split_user_host_path(const char *s, char **userp, char **hostp, char **pathp)
{
	char *tmp, *cp, *user = NULL, *host = NULL, *path = NULL;
	bool inbrackets = false;

	if (!(tmp = strdup(s))) {
		pr_err("stdrup: %s", strerror(errno));
		return NULL;
	}

	user = NULL;
	host = NULL;
	path = tmp;
	for (cp = tmp; *cp; cp++) {
		if (*cp == '@' && (cp > tmp) && *(cp - 1) != '\\' && user == NULL) {
			/* cp is non-escaped '@', so this '@' is the
			 * delimitater between username and host. */
			*cp = '\0';
			user = tmp;
			host = cp + 1;
		}
		if (*cp == '[')
			inbrackets = true;
		if (*cp == ']')
			inbrackets = false;
		if (*cp == ':' && (cp > tmp) && *(cp - 1) != '\\') {
			if (!inbrackets) {
				/* cp is non-escaped ':' and not in
				 * brackets for IPv6 address
				 * notation. So, this ':' is the
				 * delimitater between host and
				 * path. */
				*cp = '\0';
				host = host == NULL ? tmp : host;
				path = cp + 1;
				break;
			}
		}
	}
	*userp = user;
	*hostp = host ? strip_brackets(host) : NULL;
	*pathp = path;
	return tmp;
}

struct target {
	char *copy;
	char *user;
	char *host;
	char *path;
};

int compare_remote(struct target *a, struct target *b)
{
	/* return 0 if a and b have the identical user@host, otherwise 1 */
	int alen, blen;

	if (a->user) {
		if (!b->user)
			return 1;
		alen = strlen(a->user);
		blen = strlen(b->user);
		if (alen != blen)
			return 1;
		if (strncmp(a->user, b->user, alen) != 0)
			return 1;
	} else if (b->user)
		return 1;

	if (a->host) {
		if (!b->host)
			return 1;
		alen = strlen(a->host);
		blen = strlen(b->host);
		if (alen != blen)
			return 1;
		if (strncmp(a->host, b->host, alen) != 0)
			return 1;
	} else if (b->host)
		return 1;

	return 0;
}

struct target *validate_targets(char **arg, int len)
{
	/* arg is array of source ... destination.
	 * There are two cases:
	 *
	 * 1. user@host:path host:path ... path, remote to local copy
	 * 2. path path ... host:path, local to remote copy.
	 *
	 * This function split user@remote:path args into struct target,
	 * and validate all remotes are identical (mscp does not support
	 * remote to remote copy).
	 */

	struct target *t, *t0;
	int n, nslash;

	if ((t = calloc(len, sizeof(struct target))) == NULL) {
		pr_err("calloc: %s", strerrno());
		return NULL;
	}
	memset(t, 0, len * sizeof(struct target));

	/* split remote:path into remote and path */
	for (n = 0; n < len; n++) {
		t[n].copy =
			split_user_host_path(arg[n], &t[n].user, &t[n].host, &t[n].path);
		if (!t[n].copy) {
			pr_err("failed to parse '%s'", arg[n]);
			goto free_target_out;
		}
	}

	/* expand remote path, e.g., empty dst path and '~' */
	for (n = 0; n < len; n++) {
		if (!t[n].host)
			continue;

		/* this target is a remote path. check the path and
		 * expand it. this part is derived from
		 * openssh-portal prepare_remote_path() function.
		 */
		char *path = t[n].path;
		if (*path == '\0' || strcmp(path, "~") == 0)
			t[n].path = strdup(".");
		else if (strncmp(path, "~/", 2) == 0) {
			if ((nslash = strspn(path + 2, "/")) == strlen(path + 2))
				t[n].path = strdup(".");
			else
				t[n].path = strdup(path + 2 + nslash);
		}
		if (!t[n].path) {
			pr_err("strdup failed: %s", strerrno());
			goto free_target_out;
		}
	}

	/* check all user@host are identical. t[len - 1] is the
	 * destination, so we need to check t[0] to t[len - 2] having
	 * the identical remote notation */
	t0 = &t[0];
	for (n = 1; n < len - 1; n++) {
		if (compare_remote(t0, &t[n]) != 0)
			goto invalid_remotes;
	}

	/* check inconsistent remote position in args */
	if (t[0].host == NULL && t[len - 1].host == NULL) {
		pr_err("no remote host given");
		goto free_split_out;
	}

	if (t[0].host != NULL && t[len - 1].host != NULL) {
		pr_err("no local path given");
		goto free_split_out;
	}

	return t;

invalid_remotes:
	pr_err("invalid remote host notation");

free_split_out:
	for (n = 0; n < len; n++)
		if (t[n].copy)
			free(t[n].copy);

free_target_out:
	free(t);
	return NULL;
}

struct mscp *m = NULL;
pthread_t tid_stat = 0;
bool interrupted = false;

void sigint_handler(int sig)
{
	interrupted = true;
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

void print_stat(bool final);

long atol_with_unit(char *value, bool i)
{
	/* value must be "\d+[kKmMgG]?" */

	char *u = value + (strlen(optarg) - 1);
	long k = i ? 1024 : 1000;
	long factor = 1;
	long v;

	switch (*u) {
	case 'k':
	case 'K':
		factor = k;
		*u = '\0';
		break;
	case 'm':
	case 'M':
		factor = k * k;
		*u = '\0';
		break;
	case 'g':
	case 'G':
		factor = k * k * k;
		*u = '\0';
		break;
	}

	v = atol(value);
	return v * factor;
}

int to_dev_null(int fd)
{
	int nfd = open("/dev/null", O_WRONLY);
	if (nfd < 0) {
		pr_err("open /dev/null: %s", strerrno());
		return -1;
	}

	if (dup2(nfd, fd) < 0) {
		pr_err("dup2: %s", strerrno());
		return -1;
	}

	close(nfd);

	return 0;
}

int main(int argc, char **argv)
{
	struct mscp_ssh_opts s;
	struct mscp_opts o;
	struct target *t;
	int pipe_fd[2];
	int ch, n, i, ret;
	int direction = 0;
	char *remote = NULL, *checkpoint_save = NULL, *checkpoint_load = NULL;
	bool quiet = false, dryrun = false, resume = false;
	int nr_options = 0;

	memset(&s, 0, sizeof(s));
	memset(&o, 0, sizeof(o));
	o.severity = MSCP_SEVERITY_WARN;

#define mscpopts "n:m:u:I:W:R:s:S:a:b:L:46vqDrl:P:F:o:i:J:c:M:C:g:pdNh"
	while ((ch = getopt(argc, argv, mscpopts)) != -1) {
		switch (ch) {
		case 'n':
			o.nr_threads = atoi(optarg);
			if (o.nr_threads < 1) {
				pr_err("invalid number of connections: %s", optarg);
				return 1;
			}
			break;
		case 'm':
			o.coremask = optarg;
			break;
		case 'u':
			o.max_startups = atoi(optarg);
			break;
		case 'I':
			o.interval = atoi(optarg);
			break;
		case 'W':
			checkpoint_save = optarg;
			break;
		case 'R':
			checkpoint_load = optarg;
			resume = true;
			break;
		case 's':
			o.min_chunk_sz = atol_with_unit(optarg, true);
			break;
		case 'S':
			o.max_chunk_sz = atol_with_unit(optarg, true);
			break;
		case 'a':
			o.nr_ahead = atoi(optarg);
			break;
		case 'b':
			o.buf_sz = atol_with_unit(optarg, true);
			break;
		case 'L':
			o.bitrate = atol_with_unit(optarg, false);
			break;
		case '4':
			s.ai_family = AF_INET;
			break;
		case '6':
			s.ai_family = AF_INET6;
			break;
		case 'v':
			o.severity++;
			break;
		case 'q':
			quiet = true;
			break;
		case 'D':
			dryrun = true;
			break;
		case 'r':
			/* for compatibility with scp */
			break;
		case 'l':
			s.login_name = optarg;
			break;
		case 'P':
			s.port = optarg;
			break;
		case 'F':
			s.config = optarg;
			break;
		case 'o':
			nr_options++;
			s.options = realloc(s.options, sizeof(char *) * (nr_options + 1));
			if (!s.options) {
				pr_err("realloc: %s", strerrno());
				return 1;
			}
			s.options[nr_options - 1] = optarg;
			s.options[nr_options] = NULL;
			break;
		case 'i':
			s.identity = optarg;
			break;
		case 'J':
			s.proxyjump = optarg;
			break;
		case 'c':
			s.cipher = optarg;
			break;
		case 'M':
			s.hmac = optarg;
			break;
		case 'C':
			s.compress = optarg;
			break;
		case 'g':
			s.ccalgo = optarg;
			break;
		case 'p':
			o.preserve_ts = true;
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

	if (quiet)
		to_dev_null(STDOUT_FILENO);

	s.password = getenv(ENV_SSH_AUTH_PASSWORD);
	s.passphrase = getenv(ENV_SSH_AUTH_PASSPHRASE);

	if ((m = mscp_init(&o, &s)) == NULL) {
		pr_err("mscp_init: %s", priv_get_err());
		return -1;
	}

	if (!resume) {
		/* normal transfer (not resume) */
		if (argc - optind < 2) {
			/* mscp needs at lease 2 (src and target) argument */
			usage(false);
			return 1;
		}
		i = argc - optind;

		if ((t = validate_targets(argv + optind, i)) == NULL)
			return -1;

		if (t[0].host) {
			/* copy remote to local */
			direction = MSCP_DIRECTION_R2L;
			remote = t[0].host;
			s.login_name = s.login_name ? s.login_name : t[0].user;
		} else {
			/* copy local to remote */
			direction = MSCP_DIRECTION_L2R;
			remote = t[i - 1].host;
			s.login_name = s.login_name ? s.login_name : t[i - 1].user;
		}

		if (mscp_set_remote(m, remote, direction) < 0) {
			pr_err("mscp_set_remote: %s", priv_get_err());
			return -1;
		}

		if (mscp_connect(m) < 0) {
			pr_err("mscp_connect: %s", priv_get_err());
			return -1;
		}

		for (n = 0; n < i - 1; n++) {
			if (mscp_add_src_path(m, t[n].path) < 0) {
				pr_err("mscp_add_src_path: %s", priv_get_err());
				return -1;
			}
		}

		if (mscp_set_dst_path(m, t[i - 1].path) < 0) {
			pr_err("mscp_set_dst_path: %s", priv_get_err());
			return -1;
		}

		/* start to scan source files and resolve their destination paths */
		if (mscp_scan(m) < 0) {
			pr_err("mscp_scan: %s", priv_get_err());
			return -1;
		}
	} else {
		/* resume a transfer from the specified checkpoint */
		char r[512];
		int d;
		if (mscp_checkpoint_get_remote(checkpoint_load, r, sizeof(r), &d) < 0) {
			pr_err("mscp_checkpoint_get_remote: %s", priv_get_err());
			return -1;
		}

		if (mscp_set_remote(m, r, d) < 0) {
			pr_err("mscp_set_remote: %s", priv_get_err());
			return -1;
		}

		/* load paths and chunks to be transferred from checkpoint */
		if (mscp_checkpoint_load(m, checkpoint_load) < 0) {
			pr_err("mscp_checkpoint_load: %s", priv_get_err());
			return -1;
		}

		if (dryrun)
			goto out;

		/* create the first ssh connection to get password or
		 * passphrase. The sftp session over it will be not
		 * used for resume transfer in actuality. ToDo:
		 * connectin managemnet should be improved. */
		if (mscp_connect(m) < 0) {
			pr_err("mscp_connect: %s", priv_get_err());
			return -1;
		}
	}

	if (dryrun) {
		ret = mscp_scan_join(m);
		goto out;
	}

	if (pthread_create(&tid_stat, NULL, print_stat_thread, NULL) < 0) {
		pr_err("pthread_create: %s", strerror(errno));
		return -1;
	}

	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		pr_err("signal: %s", strerror(errno));
		return -1;
	}

	ret = mscp_start(m);
	if (ret < 0)
		pr_err("mscp_start: %s", priv_get_err());

	ret = mscp_join(m);

	pthread_cancel(tid_stat);
	pthread_join(tid_stat, NULL);

	print_stat(true);
	print_cli("\n"); /* final output */
out:
	if (interrupted)
		ret = 1;

	if ((dryrun || ret != 0) && checkpoint_save) {
		print_cli("save checkpoint to %s\n", checkpoint_save);
		if (mscp_checkpoint_save(m, checkpoint_save) < 0) {
			pr_err("mscp_checkpoint_save: %s", priv_get_err());
			return -1;
		}
	}

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
		snprintf(buf, sizeof(buf), "%02d:%02d    ", (int)(floor(elapsed / 60)),
			 (int)round(elapsed) % 60);
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
	snprintf(buf, sizeof(buf), "%02d:%02d ETA", (int)floor(eta / 60),
		 (int)round(eta) % 60);

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
		snprintf(buf + bar_width, sizeof(buf) - bar_width, " %3d%% ",
			 (int)floor(percent));
	}

	print_cli("\r\033[K"
		  "%s%s",
		  buf, suffix);
}

void print_progress(struct timeval *b, struct timeval *a, size_t total, size_t last,
		    size_t done, bool final)
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
		print_cli("\r\033[K"
			  "total 0 byte transferred");
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

	snprintf(suffix, sizeof(suffix), "%4.1lf%s/%.1lf%s %6.1f%s  %s", done_round,
		 byte_units[byte_du], total_round, byte_units[byte_tu], bps,
		 bps_units[bps_u], calculate_eta(total - done, done - last, b, a, final));

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
	struct mscp_stats s;
	char buf[8192];
	int timeout;

	gettimeofday(&x.after, NULL);
	if (calculate_timedelta(&x.before, &x.after) > 1 || final) {
		mscp_get_stats(m, &s);
		x.total = s.total;
		x.done = s.done;
		print_progress(!final ? &x.before : &x.start, &x.after, x.total,
			       !final ? x.last : 0, x.done, final);
		x.before = x.after;
		x.last = x.done;
	}
}

void *print_stat_thread(void *arg)
{
	struct mscp_stats s;
	char buf[8192];

	memset(&x, 0, sizeof(x));
	gettimeofday(&x.start, NULL);
	x.before = x.start;

	while (true) {
		print_stat(false);
		sleep(1);
	}

	return NULL;
}
