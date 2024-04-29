/* SPDX-License-Identifier: GPL-3.0-only */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <ssh.h>
#include <mscp.h>
#include <strerrno.h>

#include "libssh/callbacks.h"
#include "libssh/options.h"

static int ssh_verify_known_hosts(ssh_session session);
static int ssh_authenticate_kbdint(ssh_session session);

static int ssh_set_opts(ssh_session ssh, struct mscp_ssh_opts *opts)
{
	ssh_set_log_level(opts->debug_level);

	if (opts->login_name &&
	    ssh_options_set(ssh, SSH_OPTIONS_USER, opts->login_name) < 0) {
		priv_set_errv("failed to set login name");
		return -1;
	}

	if (opts->port && ssh_options_set(ssh, SSH_OPTIONS_PORT_STR, opts->port) < 0) {
		priv_set_errv("failed to set port number");
		return -1;
	}

	if (opts->ai_family &&
	    ssh_options_set(ssh, SSH_OPTIONS_AI_FAMILY, &opts->ai_family) < 0) {
		priv_set_errv("failed to set address family");
		return -1;
	}

	if (opts->identity &&
	    ssh_options_set(ssh, SSH_OPTIONS_IDENTITY, opts->identity) < 0) {
		priv_set_errv("failed to set identity");
		return -1;
	}

	if (opts->cipher) {
		if (ssh_options_set(ssh, SSH_OPTIONS_CIPHERS_C_S, opts->cipher) < 0) {
			priv_set_errv("failed to set cipher for client to server");
			return -1;
		}
		if (ssh_options_set(ssh, SSH_OPTIONS_CIPHERS_S_C, opts->cipher) < 0) {
			priv_set_errv("failed to set cipher for server to client");
			return -1;
		}
	}

	if (opts->hmac) {
		if (ssh_options_set(ssh, SSH_OPTIONS_HMAC_C_S, opts->hmac) < 0) {
			priv_set_errv("failed to set hmac for client to server");
			return -1;
		}
		if (ssh_options_set(ssh, SSH_OPTIONS_HMAC_S_C, opts->hmac) < 0) {
			priv_set_errv("failed to set hmac for server to client");
			return -1;
		}
	}

	if (opts->compress &&
	    ssh_options_set(ssh, SSH_OPTIONS_COMPRESSION, opts->compress) < 0) {
		priv_set_errv("failed to enable ssh compression");
		return -1;
	}

	if (opts->ccalgo && ssh_options_set(ssh, SSH_OPTIONS_CCALGO, opts->ccalgo) < 0) {
		priv_set_errv("failed to set cclago");
		return -1;
	}

	/* if NOT specified to enable Nagle's algorithm, disable it (set TCP_NODELAY) */
	if (!opts->enable_nagle) {
		int v = 1;
		if (ssh_options_set(ssh, SSH_OPTIONS_NODELAY, &v) < 0) {
			priv_set_errv("failed to set TCP_NODELAY");
			return -1;
		}
	}

	if (opts->config && ssh_options_parse_config(ssh, opts->config) < 0) {
		priv_set_errv("failed to parse ssh_config: %s", opts->config);
		return -1;
	}

	if (opts->proxyjump) {
		char buf[256];
		memset(buf, 0, sizeof(buf));
		snprintf(buf, sizeof(buf), "proxyjump=%s", opts->proxyjump);
		if (ssh_config_parse_string(ssh, buf) != SSH_OK) {
			priv_set_errv("failed to set ssh option: %s", buf);
			return -1;
		}
	}

	if (opts->options) {
		int n;
		for (n = 0; opts->options[n]; n++) {
			if (ssh_config_parse_string(ssh, opts->options[n]) != SSH_OK) {
				priv_set_errv("failed to set ssh option: %s",
					      opts->options[n]);
				return -1;
			}
		}
	}

	return 0;
}

static int ssh_authenticate(ssh_session ssh, struct mscp_ssh_opts *opts)
{
	int auth_bit_mask;
	int ret;

	/* none method */
	ret = ssh_userauth_none(ssh, NULL);
	if (ret == SSH_AUTH_SUCCESS)
		return 0;

	auth_bit_mask = ssh_userauth_list(ssh, NULL);
	if (auth_bit_mask & SSH_AUTH_METHOD_NONE &&
	    ssh_userauth_none(ssh, NULL) == SSH_AUTH_SUCCESS)
		return 0;

	auth_bit_mask = ssh_userauth_list(ssh, NULL);
	if (auth_bit_mask & SSH_AUTH_METHOD_PUBLICKEY) {
		char *p = opts->passphrase ? opts->passphrase : NULL;
		if (ssh_userauth_publickey_auto(ssh, NULL, p) == SSH_AUTH_SUCCESS)
			return 0;
	}

	auth_bit_mask = ssh_userauth_list(ssh, NULL);
	if (auth_bit_mask & SSH_AUTH_METHOD_PASSWORD) {
		if (!opts->password) {
			char buf[128] = {};
			if (ssh_getpass("Password: ", buf, sizeof(buf), 0, 0) < 0) {
				priv_set_errv("ssh_getpass failed");
				return -1;
			}
			if (!(opts->password = strndup(buf, sizeof(buf)))) {
				priv_set_errv("strndup: %s", strerrno());
				return -1;
			}
		}

		if (ssh_userauth_password(ssh, NULL, opts->password) == SSH_AUTH_SUCCESS)
			return 0;
	}

	auth_bit_mask = ssh_userauth_list(ssh, NULL);
	if (auth_bit_mask & SSH_AUTH_METHOD_INTERACTIVE) {
		if (ssh_authenticate_kbdint(ssh) == SSH_AUTH_SUCCESS)
			return 0;
	}

	return -1;
}

static int ssh_cache_passphrase(const char *prompt, char *buf, size_t len, int echo,
				int verify, void *userdata)
{
	struct mscp_ssh_opts *opts = userdata;

	/* This function is called on the first time for importing
	 * priv key file with passphrase. It is not called on the
	 * second time or after because cached passphrase is passed
	 * to ssh_userauth_publickey_auto(). */

	/* ToDo: use
	 * ssh_userauth_publickey_auto_get_current_identity() to print
	 * id for which we ask passphrase */

	if (ssh_getpass("Passphrase: ", buf, len, echo, verify) < 0)
		return -1;

	/* cache the passphrase */
	if (opts->passphrase)
		free(opts->passphrase);

	if (!(opts->passphrase = strndup(buf, len))) {
		priv_set_errv("strndup: %s", strerrno());
		return -1;
	}

	return 0;
}

static struct ssh_callbacks_struct cb = {
	.auth_function = ssh_cache_passphrase,
	.userdata = NULL,
};

static ssh_session ssh_init_session(const char *sshdst, struct mscp_ssh_opts *opts)
{
	ssh_session ssh = ssh_new();

	ssh_callbacks_init(&cb);
	cb.userdata = opts;
	ssh_set_callbacks(ssh, &cb);

	if (ssh_options_set(ssh, SSH_OPTIONS_HOST, sshdst) != SSH_OK) {
		priv_set_errv("failed to set destination host");
		goto free_out;
	}

	if (ssh_set_opts(ssh, opts) != 0)
		goto free_out;

	if (ssh_connect(ssh) != SSH_OK) {
		priv_set_errv("failed to connect ssh server: %s", ssh_get_error(ssh));
		goto free_out;
	}

	if (ssh_authenticate(ssh, opts) != 0) {
		priv_set_errv("authentication failed: %s", ssh_get_error(ssh));
		goto disconnect_out;
	}

	if (ssh_verify_known_hosts(ssh) != 0) {
		priv_set_errv("ssh_veriy_known_hosts failed");
		goto disconnect_out;
	}

	return ssh;

disconnect_out:
	ssh_disconnect(ssh);
free_out:
	ssh_free(ssh);
	return NULL;
}

sftp_session ssh_init_sftp_session(const char *sshdst, struct mscp_ssh_opts *opts)
{
	sftp_session sftp;
	ssh_session ssh = ssh_init_session(sshdst, opts);

	if (!ssh)
		return NULL;

	sftp = sftp_new(ssh);
	if (!sftp) {
		priv_set_errv("failed to allocate sftp session: %s", ssh_get_error(ssh));
		goto err_out;
	}

	if (sftp_init(sftp) != SSH_OK) {
		priv_set_errv("failed to initialize sftp session: err code %d",
			      sftp_get_error(sftp));
		goto err_out;
	}

	return sftp;
err_out:
	ssh_disconnect(ssh);
	ssh_free(ssh);
	return NULL;
}

/* copied from https://api.libssh.org/stable/libssh_tutor_guided_tour.html*/
static int ssh_verify_known_hosts(ssh_session session)
{
	enum ssh_known_hosts_e state;
	unsigned char *hash = NULL;
	ssh_key srv_pubkey = NULL;
	size_t hlen;
	char buf[10];
	char *hexa;
	char *p;
	int cmp;
	int rc;

	rc = ssh_get_server_publickey(session, &srv_pubkey);
	if (rc < 0) {
		return -1;
	}

	rc = ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash, &hlen);
	ssh_key_free(srv_pubkey);
	if (rc < 0) {
		return -1;
	}

	state = ssh_session_is_known_server(session);
	switch (state) {
	case SSH_KNOWN_HOSTS_OK:
		/* OK */

		break;
	case SSH_KNOWN_HOSTS_CHANGED:
		fprintf(stderr, "Host key for server changed: it is now:\n");
		//ssh_print_hexa("Public key hash", hash, hlen);
		fprintf(stderr, "For security reasons, connection will be stopped\n");
		ssh_clean_pubkey_hash(&hash);

		return -1;
	case SSH_KNOWN_HOSTS_OTHER:
		fprintf(stderr, "The host key for this server was not found but an other"
				"type of key exists.\n");
		fprintf(stderr,
			"An attacker might change the default server key to"
			"confuse your client into thinking the key does not exist\n");
		ssh_clean_pubkey_hash(&hash);

		return -1;
	case SSH_KNOWN_HOSTS_NOT_FOUND:
		fprintf(stderr, "Could not find known host file.\n");
		fprintf(stderr, "If you accept the host key here, the file will be"
				"automatically created.\n");

		/* FALL THROUGH to SSH_SERVER_NOT_KNOWN behavior */

	case SSH_KNOWN_HOSTS_UNKNOWN:
		hexa = ssh_get_hexa(hash, hlen);
		fprintf(stderr, "The server is unknown. Do you trust the host key?\n");
		fprintf(stderr, "Public key hash: %s\n", hexa);
		fprintf(stderr, "(yes/no): ");
		ssh_string_free_char(hexa);
		ssh_clean_pubkey_hash(&hash);
		p = fgets(buf, sizeof(buf), stdin);
		if (p == NULL) {
			return -1;
		}

		cmp = strncasecmp(buf, "yes", 3);
		if (cmp != 0) {
			return -1;
		}

		rc = ssh_session_update_known_hosts(session);
		if (rc < 0) {
			priv_set_errv("%s", ssh_get_error(session));
			return -1;
		}

		break;
	case SSH_KNOWN_HOSTS_ERROR:
		fprintf(stderr, "known hosts error: %s", ssh_get_error(session));
		ssh_clean_pubkey_hash(&hash);
		return -1;
	}

	ssh_clean_pubkey_hash(&hash);
	return 0;
}

static int ssh_authenticate_kbdint(ssh_session ssh)
{
	/* Copied and bit modified from
	 * https://api.libssh.org/stable/libssh_tutor_authentication.html */
	int rc;

	rc = ssh_userauth_kbdint(ssh, NULL, NULL);
	while (rc == SSH_AUTH_INFO) {
		const char *name, *instruction;
		int nprompts, iprompt;

		name = ssh_userauth_kbdint_getname(ssh);
		instruction = ssh_userauth_kbdint_getinstruction(ssh);
		nprompts = ssh_userauth_kbdint_getnprompts(ssh);

		if (strlen(name) > 0)
			printf("%s\n", name);
		if (strlen(instruction) > 0)
			printf("%s\n", instruction);
		for (iprompt = 0; iprompt < nprompts; iprompt++) {
			const char *prompt;
			char echo;

			prompt = ssh_userauth_kbdint_getprompt(ssh, iprompt, &echo);
			if (echo) {
				char buf[128], *ptr;

				printf("%s", prompt);
				if (fgets(buf, sizeof(buf), stdin) == NULL)
					return SSH_AUTH_ERROR;
				buf[sizeof(buf) - 1] = '\0';
				if ((ptr = strchr(buf, '\n')) != NULL)
					*ptr = '\0';
				if (ssh_userauth_kbdint_setanswer(ssh, iprompt, buf) < 0)
					return SSH_AUTH_ERROR;
				memset(buf, 0, strlen(buf));
			} else {
				char *ptr;
				ptr = getpass(prompt);
				if (ssh_userauth_kbdint_setanswer(ssh, iprompt, ptr) < 0)
					return SSH_AUTH_ERROR;
			}
		}
		rc = ssh_userauth_kbdint(ssh, NULL, NULL);
	}
	return rc;
}

void ssh_sftp_close(sftp_session sftp)
{
	ssh_session ssh = sftp_ssh(sftp);
	/* XXX: sftp_free is stuck in ssh_poll_ctx_dopoll() when build type is Release.
	 * skip sftp_free inappropriately...
	 */
	//sftp_free(sftp);
	ssh_disconnect(ssh);
	ssh_free(ssh);
}

const char **mscp_ssh_ciphers(void)
{
	return ssh_ciphers();
}

const char **mscp_ssh_hmacs(void)
{
	return ssh_hmacs();
}
