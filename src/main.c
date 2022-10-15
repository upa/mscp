#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <util.h>
#include <ssh.h>
#include <file.h>
#include <platform.h>


#define DEFAULT_MIN_CHUNK_SZ      (64 << 20)       /* 64MB */

void usage(bool print_help) {
        printf("sscp: super scp, copy files over multiple ssh connections\n"
               "\n"
               "Usage: sscp [rvC] [-n max_conns] [-s min_chunk_sz] [-S max_chunk_sz]\n"
               "            [-l login_name] [-p port] [-i identity_file]\n"
               "            [-c cipher_spec] source ... target_directory\n"
               "\n");
               
        if (!print_help)
                return;

        printf("    -r                 expand directory recusrively\n"
               "    -n NR_CONNECTIONS  max number of connections (default: # of cpu cores)\n"
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

int main(int argc, char **argv)
{
	struct ssh_opts opts;
        int nr_conn = nr_cpus();
        bool recursive = false;
        int min_chunk_sz = DEFAULT_MIN_CHUNK_SZ;
        int max_chunk_sz = 0;
        char ch;

        memset(&opts, 0, sizeof(opts));

	while ((ch = getopt(argc, argv, "r:n:s:S:l:p:i:c:Cvh")) != -1) {
		switch (ch) {
                case 'r':
                        recursive = true;
                        break;
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

        printf("opts.port %s\n", opts.port);

        int n;
        for (n = 0; n < argc; n++) {
                printf("%d %s\n", n, argv[n]);
        }
        printf("optind %d", optind);

	return 0;
}
