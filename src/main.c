#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <list.h>
#include <util.h>
#include <ssh.h>
#include <file.h>
#include <atomic.h>
#include <platform.h>

int verbose = 0; /* util.h */

#define DEFAULT_MIN_CHUNK_SZ      (64 << 20)       /* 64MB */

struct sscp {
        char                    *host;  /* remote host (and username) */
        sftp_session            ctrl;   /* control sftp session */

        struct list_head        file_list;
        struct list_head        chunk_list;
        lock                    chunk_lock;  /* lock for chunk list */

        char *target;
};

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
        int nr_conn = nr_cpus();
        int min_chunk_sz = DEFAULT_MIN_CHUNK_SZ;
        int max_chunk_sz = 0;
        int ret = 0;
        char ch;

        memset(&opts, 0, sizeof(opts));
        memset(&sscp, 0, sizeof(sscp));
        INIT_LIST_HEAD(&sscp.file_list);
        INIT_LIST_HEAD(&sscp.chunk_list);
        lock_init(&sscp.chunk_lock);

	while ((ch = getopt(argc, argv, "n:s:S:l:p:i:c:Cvh")) != -1) {
		switch (ch) {
                case 'n':
                        nr_conn = atoi(optarg);
                        if (nr_conn < 1) {
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

        /* check target is directory */
        ret = file_is_directory(sscp.target,
                                file_find_hostname(sscp.target) ? sscp.ctrl : NULL);
        if (ret < 0)
                return 1;
        if (ret == 0) {
                pr_err("target must be directory\n");
                return 1;
        }

        /* fill file list */
        ret = file_fill(sscp.ctrl, &sscp.file_list, &argv[optind], argc - optind - 1);
        if (ret < 0) {
                ssh_sftp_close(sscp.ctrl);
                return 1;
        }
        ret = file_fill_dst(sscp.target, &sscp.file_list);
        if (ret < 0){
                ssh_sftp_close(sscp.ctrl);
                return -1;
        }
#ifdef DEBUG
        file_dump(&sscp.file_list);
#endif

        /* fill chunk list */
        ret = chunk_fill(&sscp.file_list, &sscp.chunk_list,
                         nr_conn, min_chunk_sz, max_chunk_sz);
        if (ret < 0) {
                ssh_sftp_close(sscp.ctrl);
                return 1;
        }
#ifdef DEBUG
        chunk_dump(&sscp.chunk_list);
#endif

        struct chunk *c;
        list_for_each_entry(c, &sscp.chunk_list, list) {
                chunk_prepare(c, sscp.ctrl);
                chunk_copy(c, sscp.ctrl, 8192);
        }


        ssh_sftp_close(sscp.ctrl);
	return 0;
}
