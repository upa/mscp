#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include <mscp.h>
#include <util.h>


#ifndef _VERSION /* passed through cmake */
#define VERSION "(unknown)"
#else
#define VERSION _VERSION
#endif


void usage(bool print_help) {
	printf("mscp v" VERSION ": copy files over multiple ssh connections\n"
	       "\n"
	       "Usage: mscp [vqDCHdNh] [-n nr_conns] [-m coremask]\n"
	       "            [-s min_chunk_sz] [-S max_chunk_sz] [-a nr_ahead] [-b buf_sz]\n"
	       "            [-l login_name] [-p port] [-i identity_file]\n"
	       "            [-c cipher_spec] [-M hmac_spec] source ... target\n"
	       "\n");

	if (!print_help)
		return;

	printf("    -n NR_CONNECTIONS  number of connections "
	       "(default: floor(log(cores)*2)+1)\n"
	       "    -m COREMASK        hex value to specify cores where threads pinned\n"
	       "    -s MIN_CHUNK_SIZE  min chunk size (default: 64MB)\n"
	       "    -S MAX_CHUNK_SIZE  max chunk size (default: filesize/nr_conn)\n"
	       "\n"
	       "    -a NR_AHEAD        number of inflight SFTP commands (default: 32)\n"
	       "    -b BUF_SZ          buffer size for i/o and transfer\n"
	       "\n"
	       "    -v                 increment verbose output level\n"
	       "    -q                 disable output\n"
	       "    -D                 dry run\n"
	       "    -r                 no effect\n"
	       "\n"
	       "    -l LOGIN_NAME      login name\n"
	       "    -p PORT            port number\n"
	       "    -i IDENTITY        identity file for public key authentication\n"
	       "    -c CIPHER          cipher spec\n"
	       "    -M HMAC            hmac spec\n"
	       "    -C                 enable compression on libssh\n"
	       "    -H                 disable hostkey check\n"
	       "    -d                 increment ssh debug output level\n"
	       "    -N                 disable tcp nodelay (default on)\n"
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
		pr_err("failed to allocate memory: %s\n", strerrno());
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
		pr_err("failed to allocate memory: %s\n", strerrno());
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
		pr_err("no remote host given\n");
		goto free_split_out;
	}

	if (t[0].remote != NULL && t[len - 1].remote != NULL) {
		pr_err("no local path given\n");
		goto free_split_out;
	}

	return t;

invalid_remotes:
	pr_err("specified remote host invalid\n");

free_split_out:
	for (n = 0; n < len; n++)
		t[n].remote ? free(t[n].remote) : free(t[n].path);

free_target_out:
	free(t);
	return NULL;
}

int main(int argc, char **argv)
{
	struct mscp_opts o;
	struct mscp *m;
	struct target *t;
	int ch, n, i;
	char *remote;

	memset(&o, 0, sizeof(o));

	while ((ch = getopt(argc, argv, "n:m:s:S:a:b:vqDrl:p:i:c:M:CHdNh")) != -1) {
		switch (ch) {
		case 'n':
			o.nr_threads = atoi(optarg);
			if (o.nr_threads < 1) {
				pr_err("invalid number of connections: %s\n", optarg);
				return 1;
			}
			break;
		case 'm':
			strncpy(o.coremask, optarg, sizeof(o.coremask));
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
			o.verbose_level++;
			break;
		case 'q':
			o.verbose_level = -1;
			break;
		case 'D':
			o.dryrun = true;
			break;
		case 'r':
			/* for compatibility with scp */
			break;
		case 'l':
			if (strlen(optarg) > MSCP_MAX_LOGIN_NAME - 1) {
				pr_err("too long login name: %s\n", optarg);
				return -1;
			}
			strncpy(o.ssh_login_name, optarg, MSCP_MAX_LOGIN_NAME - 1);
			break;
		case 'p':
			if (strlen(optarg) > MSCP_MAX_PORT_STR - 1) {
				pr_err("too long port string: %s\n", optarg);
				return -1;
			}
			strncpy(o.ssh_port, optarg, MSCP_MAX_PORT_STR);
			break;
		case 'i':
			if (strlen(optarg) > MSCP_MAX_IDENTITY_PATH - 1) {
				pr_err("too long identity path: %s\n", optarg);
				return -1;
			}
			strncpy(o.ssh_identity, optarg, MSCP_MAX_IDENTITY_PATH);
			break;
		case 'c':
			if (strlen(optarg) > MSCP_MAX_CIPHER_STR - 1) {
				pr_err("too long cipher string: %s\n", optarg);
				return -1;
			}
			strncpy(o.ssh_cipher_spec, optarg, MSCP_MAX_CIPHER_STR);
			break;
		case 'M':
			if (strlen(optarg) > MSCP_MAX_HMACP_STR - 1) {
				pr_err("too long hmac string: %s\n", optarg);
				return -1;
			}
			strncpy(o.ssh_hmac_spec, optarg, MSCP_MAX_HMACP_STR);
			break;
		case 'C':
			o.ssh_compress_level++;
			break;
		case 'H':
			o.ssh_no_hostkey_check = true;
			break;
		case 'd':
			o.ssh_debug_level++;
			break;
		case 'N':
			o.ssh_disable_tcp_nodely = true;
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
		o.direction = MSCP_DIRECTION_R2L;
		remote = t[0].remote;
	} else {
		/* copy local to remote */
		o.direction = MSCP_DIRECTION_L2R;
		remote = t[i - 1].remote;
	}

	if ((m = mscp_init(remote, &o)) == NULL)
		return -1;

	if (mscp_connect(m) < 0)
		return -1;

	for (n = 0; n < i - 1; n++) {
		if (mscp_add_src_path(m, t[n].path) < 0)
			return -1;
	}

	if (mscp_set_dst_path(m, t[i - 1].path) < 0)
		return -1;

	if (mscp_prepare(m) < 0)
		return -1;

	if (mscp_start(m) < 0)
		return -1;

	mscp_cleanup(m);
	mscp_free(m);

	return 0;
}
