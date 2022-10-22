#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
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
#define DEFAULT_BUF_SZ          32768           /* CHANNEL_MAX_PACKET in libssh */
/* XXX: passing over CHANNEL_MAX_PACKET bytes to sftp_write stalls */

struct sscp {
        char                    *host;  /* remote host (and username) */
        struct ssh_opts         *opts;  /* ssh parameters */
        sftp_session            ctrl;   /* control sftp session */


        struct list_head        file_list;
        struct list_head        chunk_list;     /* stack of chunks */
        lock                    chunk_lock;  /* lock for chunk list */

        char    *target;

        int     buf_sz;
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

void stop_all(int sig)
{
        int n;

        pr("stopping...\n");
        for (n = 0; n < nr_threads; n++) {
                pthread_cancel(threads[n].tid);
        }
        pthread_cancel(mtid);
}


void usage(bool print_help) {
        printf("sscp: super scp, copy files over multiple ssh connections\n"
               "\n"
               "Usage: sscp [rvC] [-n max_conns] [-s min_chunk_sz] [-S max_chunk_sz]\n"
               "            [-l login_name] [-p port] [-i identity_file]\n"
               "            [-c cipher_spec] source ... target_directory\n"
               "\n");
               
        if (!print_help)
                return;

        printf("    -n NR_CONNECTIONS  max number of connections (default: # of cpu cores)\n"
               "    -s MIN_CHUNKSIZE   min chunk size (default: 64MB)\n"
               "    -S MAX_CHUNKSIZE   max chunk size (default: filesize / nr_conn)\n"
               "    -b BUFFER_SIZE     buffer size for read/write (default 32768B)\n"
               "                       Note that this value is derived from\n"
               "                       CHANNEL_MAX_PACKET in libssh. Recommend NOT\n"
               "                       exceeds the default value.\n"
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
        sscp.buf_sz = DEFAULT_BUF_SZ;

        nr_threads = nr_cpus();

	while ((ch = getopt(argc, argv, "n:s:S:b:l:p:i:c:Cvh")) != -1) {
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
                        sscp.buf_sz = atoi(optarg);
                        if (sscp.buf_sz < 1) {
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
        if (signal(SIGINT, stop_all) == SIG_ERR) {
                pr_err("cannot set signal: %s\n", strerrno());
                ret = 1;
                goto out;
        }

        /* spawn threads */
        threads = calloc(nr_threads, sizeof(struct sscp_thread));
        memset(threads, 0, nr_threads * sizeof(struct sscp_thread));
        for (n = 0; n < nr_threads; n++) {
                struct sscp_thread *t = &threads[n];
                t->sscp = &sscp;
                t->finished = false;
                ret = pthread_create(&t->tid, NULL, sscp_copy_thread, t);
                if (ret < 0) {
                        pr_err("pthread_create error: %d\n", ret);
                        stop_all(0);
                        goto join_out;
                }
        }

        /* spawn count thread */
        ret = pthread_create(&mtid, NULL, sscp_monitor_thread, &sscp);
        if (ret < 0) {
                pr_err("pthread_create error: %d\n", ret);
                stop_all(0);
                goto join_out;
        }


join_out:
        /* waiting for threads join... */
        for (n = 0; n < nr_threads; n++)
                if (threads[n].tid)
                        pthread_join(threads[n].tid, NULL);

        if (mtid != 0)
                pthread_join(mtid, NULL);

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
        sftp_session sftp;
        struct chunk *c;

        /* create sftp session */
        sftp = ssh_make_sftp_session(sscp->host, sscp->opts);
        if (!sftp)
                return NULL;

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

                if (chunk_copy(c, sftp, sscp->buf_sz, &t->done) < 0)
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

        return (double)diff / sec * 8;
}

void *sscp_monitor_thread(void *arg)
{
        struct sscp *sscp = arg;
        struct sscp_thread *t;
        struct timeval a, b;
        struct file *f;
        bool all_done;
        size_t total, total_round, done, last;
        int percent;
        double bps;
        char *bps_units[] = { "bps", "Kbps", "Mbps", "Gbps" };
        char *byte_units[] = { "B", "KB", "MB", "GB", "TB" };
        int n, bps_u, byte_tu, byte_du;

        total = 0;
        done = 0;
        last = 0;

        /* get total byte to be transferred */
        list_for_each_entry(f, &sscp->file_list, list) {
                total += f->size;
        }
        total_round = total;
        for (byte_tu = 0; total_round > 1000 && byte_tu < 5; byte_tu++)
                total_round /= 1024;

        while (1) {

                gettimeofday(&b, NULL);
                sleep(1);

                all_done = true;
                done = 0;

                for (n = 0; n < nr_threads; n++) {
                        t = &threads[n];
                        done += t->done;
                        if (!t->finished)
                                all_done = false;
                }

                gettimeofday(&a, NULL);

                percent = floor(((double)(done) / (double)total) * 100);
                for (byte_du = 0; done > 1000 && byte_du < 5; byte_du++) done /= 1024;

                bps = calculate_bps(done - last, &b, &a);
                for (bps_u = 0; bps > 1000 && bps_u < 4; bps_u++) bps /= 1000;

                printf("%d%% (%lu%s/%lu%s) %.2f %s\n",
                       percent,
                       done, byte_units[byte_du], total_round, byte_units[byte_tu],
                       bps, bps_units[bps_u]);

                if (all_done || total == done)
                        break;

                last = done;
                b = a;
        }

        return NULL;
}
