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
#include <atomic.h>
#include <platform.h>

int verbose = 0; /* util.h */


#define DEFAULT_MIN_CHUNK_SZ    (64 << 20)      /* 64MB */
#define DEFAULT_SFTP_BUF_SZ     131072          /* derived from qemu/block/ssh.c */
#define DEFAULT_IO_BUF_SZ       DEFAULT_SFTP_BUF_SZ
/* XXX: need to investigate max buf size for sftp_read/sftp_write */

struct sscp {
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

struct sscp_thread {
        struct sscp     *sscp;
        sftp_session    sftp;

        pthread_t       tid;
        size_t          done;           /* copied bytes */
        bool            finished;
};

void *sscp_copy_thread(void *arg);
void *sscp_monitor_thread(void *arg);

static pthread_t mtid;
struct sscp_thread *threads;
int nr_threads;

void stop_copy_threads(int sig)
{
        int n;

        pr("stopping...\n");
        for (n = 0; n < nr_threads; n++) {
                pthread_cancel(threads[n].tid);
        }
}


void usage(bool print_help) {
        printf("sscp: super scp, copy files over multiple ssh connections\n"
               "\n"
               "Usage: sscp [Cvh] [-n max_conns] [-s min_chunk_sz] [-S max_chunk_sz]\n"
               "            [-b sftp_buf_sz] [-B io_buf_sz]\n"
               "            [-l login_name] [-p port] [-i identity_file]\n"
               "            [-c cipher_spec] source ... target_directory\n"
               "\n");
               
        if (!print_help)
                return;

        printf("    -n NR_CONNECTIONS  max number of connections (default: # of cpu cores)\n"
               "    -s MIN_CHUNK_SIZE  min chunk size (default: 64MB)\n"
               "    -S MAX_CHUNK_SIZE  max chunk size (default: filesize / nr_conn)\n"
               "    -b SFTP_BUF_SIZE   buf size for sftp_read/write (default 131072B)\n"
               "    -B IO_BUF_SIZE     buf size for read/write (default 131072B)\n"
               "                       Note that this value is derived from\n"
               "                       qemu/block/ssh.c. need investigation...\n"
               "\n"
               "    -l LOGIN_NAME      login name\n"
               "    -p PORT            port number\n"
               "    -i IDENTITY        identity file for publickey authentication\n"
               "    -c CIPHER          cipher spec, see `ssh -Q cipher`\n"
               "    -C                 enable compression on libssh\n"
               "    -v                 increment output level\n"
               "    -h                 print this help\n"
               "\n");

        printf("  Note:\n"
               "    Not similar to scp and rsync, target in sscp must be directory\n"
               "    (at present). This means that sscp cannot change file names.\n"
               "    sscp copies file(s) into a directory.\n"
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
        struct sscp sscp;
	struct ssh_opts opts;
        int min_chunk_sz = DEFAULT_MIN_CHUNK_SZ;
        int max_chunk_sz = 0;
        int ret = 0, n;
        char ch;

        memset(&opts, 0, sizeof(opts));
        memset(&sscp, 0, sizeof(sscp));
        INIT_LIST_HEAD(&sscp.file_list);
        INIT_LIST_HEAD(&sscp.chunk_list);
        lock_init(&sscp.chunk_lock);
        sscp.sftp_buf_sz = DEFAULT_SFTP_BUF_SZ;
        sscp.io_buf_sz = DEFAULT_IO_BUF_SZ;

        nr_threads = nr_cpus();

	while ((ch = getopt(argc, argv, "n:s:S:b:B:l:p:i:c:Cvh")) != -1) {
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
                        sscp.sftp_buf_sz = atoi(optarg);
                        if (sscp.sftp_buf_sz < 1) {
                                pr_err("invalid buffer size: %s\n", optarg);
                                return -1;
                        }
                        break;
                case 'B':
                        sscp.io_buf_sz = atoi(optarg);
                        if (sscp.io_buf_sz < 1) {
                                pr_err("invalid buffer size: %s\n", optarg);
                                return -1;
                        }
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
		case 'v':
			opts.debuglevel++;
                        verbose++;
			break;
                case 'h':
                        usage(true);
                        return 1;
                default:
                        usage(false);
                        return 1;
		}
        }

        if (max_chunk_sz > 0 && min_chunk_sz > max_chunk_sz) {
                pr_err("smaller max chunk size than min chunk size: %d < %d\n",
                       max_chunk_sz, min_chunk_sz);
                return 1;
        }

        if (argc - optind < 2) {
                /* sscp needs at lease 2 (src and target) argument */
                usage(false);
                return 1;
        }

        sscp.target = argv[argc - 1];

        /* create control session */
        sscp.host = find_hostname(optind, argc, argv);
        if (!sscp.host) {
                pr_err("no remote host given\n");
                return 1;
        }
        sscp.ctrl = ssh_make_sftp_session(sscp.host, &opts);
        if (!sscp.ctrl)
                return 1;
        sscp.opts = &opts; /* save ssh-able ssh_opts */

        /* check target is directory */
        ret = file_is_directory(sscp.target,
                                file_find_hostname(sscp.target) ? sscp.ctrl : NULL);
        if (ret < 0)
                goto out;
        if (ret == 0) {
                pr_err("target must be directory\n");
                goto out;
        }

        /* fill file list */
        ret = file_fill(sscp.ctrl, &sscp.file_list, &argv[optind], argc - optind - 1);
        if (ret < 0)
                goto out;

        ret = file_fill_dst(sscp.target, &sscp.file_list);
        if (ret < 0)
                goto out;

#ifdef DEBUG
        file_dump(&sscp.file_list);
#endif

        /* fill chunk list */
        ret = chunk_fill(&sscp.file_list, &sscp.chunk_list,
                         nr_threads, min_chunk_sz, max_chunk_sz);
        if (ret < 0)
                goto out;

#ifdef DEBUG
        chunk_dump(&sscp.chunk_list);
#endif

        /* register SIGINT to stop thrads */
        if (signal(SIGINT, stop_copy_threads) == SIG_ERR) {
                pr_err("cannot set signal: %s\n", strerrno());
                ret = 1;
                goto out;
        }

        /* prepare thread instances */
        threads = calloc(nr_threads, sizeof(struct sscp_thread));
        memset(threads, 0, nr_threads * sizeof(struct sscp_thread));
        for (n = 0; n < nr_threads; n++) {
                struct sscp_thread *t = &threads[n];
                t->sscp = &sscp;
                t->finished = false;
                t->sftp = ssh_make_sftp_session(sscp.host, sscp.opts);
                if (!t->sftp)
                        goto join_out;
        }

        /* spawn count thread */
        ret = pthread_create(&mtid, NULL, sscp_monitor_thread, &sscp);
        if (ret < 0) {
                pr_err("pthread_create error: %d\n", ret);
                stop_copy_threads(0);
                goto join_out;
        }

        /* save start time */
        gettimeofday(&sscp.start, NULL);

        /* spawn threads */
        for (n = 0; n < nr_threads; n++) {
                struct sscp_thread *t = &threads[n];
                ret = pthread_create(&t->tid, NULL, sscp_copy_thread, t);
                if (ret < 0) {
                        pr_err("pthread_create error: %d\n", ret);
                        stop_copy_threads(0);
                        goto join_out;
                }
        }

join_out:
        /* waiting for threads join... */
        for (n = 0; n < nr_threads; n++)
                if (threads[n].tid)
                        pthread_join(threads[n].tid, NULL);

        if (mtid != 0) {
                pthread_cancel(mtid);
                pthread_join(mtid, NULL);
        }

out:
        if (sscp.ctrl)
                ssh_sftp_close(sscp.ctrl);

	return ret;
}

void sscp_copy_thread_cleanup(void *arg)
{
        struct sscp_thread *t = arg;
        if (t->sftp)
                ssh_sftp_close(t->sftp);
        t->finished = true;
}

void *sscp_copy_thread(void *arg)
{
        struct sscp_thread *t = arg;
        struct sscp *sscp = t->sscp;
        sftp_session sftp = t->sftp;
        struct chunk *c;

        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
        pthread_cleanup_push(sscp_copy_thread_cleanup, t);

        while (1) {
                lock_acquire(&sscp->chunk_lock);
                c = chunk_acquire(&sscp->chunk_list);
                lock_release(&sscp->chunk_lock);

                if (!c)
                        break; /* no more chunks */

                if (chunk_prepare(c, sftp) < 0)
                        break;

                if (chunk_copy(c, sftp,
                               sscp->sftp_buf_sz, sscp->io_buf_sz, &t->done) < 0)
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

static void print_progress(double percent, char *suffix)
{
        int n, thresh, bar_width;
        struct winsize ws;
        char buf[128];

        /*
         * [=======>   ] XX.X% SUFFIX
         */

        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) < 0)
                return; /* XXX */

        fputs("\r\033[K", stderr);

        bar_width = ws.ws_col - strlen(suffix) - 8;
        if (bar_width < 0)
                goto suffix_only;

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

        fputs(buf, stderr);
suffix_only:
        fputs(suffix, stderr);
        fflush(stderr);
}

void *sscp_monitor_thread(void *arg)
{
        struct sscp *sscp = arg;
        struct sscp_thread *t;
        struct timeval a, b;
        struct file *f;
        char suffix[128];
        bool all_done;
        size_t total, total_round, done, last;
        int percent;
        double bps;
        char *bps_units[] = { "B/s", "KB/s", "MB/s", "GB/s" };
        char *byte_units[] = { "B", "KB", "MB", "GB", "TB", "PB" };
        int n, bps_u, byte_tu, byte_du;

#define array_size(a) (sizeof(a) / sizeof(a[0]))

        total = 0;
        done = 0;
        last = 0;

        /* get total byte to be transferred */
        list_for_each_entry(f, &sscp->file_list, list) {
                total += f->size;
        }
        total_round = total;
        for (byte_tu = 0; total_round > 1000 && byte_tu < array_size(byte_units) - 1;
             byte_tu++)
                total_round /= 1024;

        while (1) {
                all_done = true;
                last = 0;
                done = 0;

                for (n = 0; n < nr_threads; n++) {
                        t = &threads[n];
                        last += t->done;
                }
                gettimeofday(&b, NULL);

                usleep(500000);

                for (n = 0; n < nr_threads; n++) {
                        t = &threads[n];
                        done += t->done;
                        if (!t->finished)
                                all_done = false;
                }
                gettimeofday(&a, NULL);

                bps = calculate_bps(done - last, &b, &a);
                for (bps_u = 0; bps > 1000 && bps_u < array_size(bps_units); bps_u++)
                        bps /= 1000;

                percent = floor(((double)(done) / (double)total) * 100);
                for (byte_du = 0;
                     done > 1000 && byte_du < array_size(byte_units) - 1;
                     byte_du++)
                        done /= 1024;

                snprintf(suffix, sizeof(suffix), "%lu%s/%lu%s %.2f%s ",
                         done, byte_units[byte_du], total_round, byte_units[byte_tu],
                         bps, bps_units[bps_u]);
                print_progress(percent, suffix);

                if (all_done || total == done)
                        break;
        }

        fputs("\n", stderr);

        return NULL;
}
