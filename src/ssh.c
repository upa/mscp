#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <ssh.h>
#include <util.h>

static int ssh_verify_known_hosts(ssh_session session);


static int ssh_set_opts(ssh_session ssh, struct ssh_opts *opts)
{
        ssh_set_log_level(opts->debuglevel);

        if (opts->login_name &&
            ssh_options_set(ssh, SSH_OPTIONS_USER, opts->login_name) < 0) {
                pr_err("failed to set login name\n");
                return -1;
        }

        if (opts->port &&
            ssh_options_set(ssh, SSH_OPTIONS_PORT_STR, opts->port) < 0) {
                pr_err("failed to set port number\n");
                return -1;
        }

        if (opts->identity &&
            ssh_options_set(ssh, SSH_OPTIONS_IDENTITY, opts->identity) < 0) {
                pr_err("failed to set identity\n");
                return -1;
        }

        if (opts->cipher) {
                if (ssh_options_set(ssh, SSH_OPTIONS_CIPHERS_C_S, opts->cipher) < 0) {
                        pr_err("failed to set cipher client to server\n");
                        return -1;
                }
                if (ssh_options_set(ssh, SSH_OPTIONS_CIPHERS_S_C, opts->cipher) < 0) {
                        pr_err("failed to set cipher client to server\n");
                        return -1;
                }
        }

        if (opts->compress &&
            ssh_options_set(ssh, SSH_OPTIONS_COMPRESSION, "yes") < 0) {
                pr_err("failed to enable ssh compression\n");
                return -1;
        }

        return 0;
}

static int ssh_authenticate(ssh_session ssh, struct ssh_opts *opts)
{
        int auth_bit_mask;
        int ret;
        
        /* none method */
        ret = ssh_userauth_none(ssh, NULL);
        if (ret == SSH_AUTH_SUCCESS)
                return 0;

        auth_bit_mask = ssh_userauth_list(ssh, NULL);

        if (auth_bit_mask & SSH_AUTH_METHOD_NONE &&
            ssh_userauth_none(ssh, NULL) == SSH_AUTH_SUCCESS) {
                return 0;
        }

        if (auth_bit_mask & SSH_AUTH_METHOD_PUBLICKEY &&
            ssh_userauth_publickey_auto(ssh, NULL, NULL) == SSH_AUTH_SUCCESS) {
                return 0;
        }

        if (auth_bit_mask & SSH_AUTH_METHOD_PASSWORD) {
                if (!opts->password) {
                        opts->password = getpass("Password: ");
                }
                if (ssh_userauth_password(ssh, NULL, opts->password) == SSH_AUTH_SUCCESS)
                        return 0;
        }

        pr_err("authentication failure: %s\n", ssh_get_error(ssh));
        return -1;
}

static ssh_session ssh_make_ssh_session(char *sshdst, struct ssh_opts *opts)
{
        ssh_session ssh = ssh_new();

        if (ssh_set_opts(ssh, opts) != 0)
                goto free_out;

        if (ssh_options_set(ssh, SSH_OPTIONS_HOST, sshdst) != SSH_OK) {
                pr_err("failed to set destination host\n");
                goto free_out;
        }

        if (ssh_connect(ssh) != SSH_OK) {
                pr_err("failed to connect ssh server: %s\n", ssh_get_error(ssh));
                goto free_out;
        }

        if (ssh_authenticate(ssh, opts) != 0) {
                pr_err("authentication failed: %s\n", ssh_get_error(ssh));
                goto disconnect_out;
        }

        if (ssh_verify_known_hosts(ssh) != 0) {
                goto disconnect_out;
        }

        return ssh;

disconnect_out:
        ssh_disconnect(ssh);
free_out:
        ssh_free(ssh);
        return NULL;
}

sftp_session ssh_make_sftp_session(char *sshdst, struct ssh_opts *opts)
{
        sftp_session sftp;
        ssh_session ssh = ssh_make_ssh_session(sshdst, opts);

        if (!ssh) {
                return NULL;
        }

        sftp = sftp_new(ssh);
        if (!sftp) {
                pr_err("failed to allocate sftp session: %s\n", ssh_get_error(ssh));
                goto err_out;
        }

        if (sftp_init(sftp) != SSH_OK) {
                pr_err("failed to initialize sftp session: err code %d\n",
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
 
        rc = ssh_get_publickey_hash(srv_pubkey,
                                    SSH_PUBLICKEY_HASH_SHA1,
                                    &hash,
                                    &hlen);
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
                fprintf(stderr, "An attacker might change the default server key to"
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
                fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
                fprintf(stderr, "Public key hash: %s\n", hexa);
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
                        fprintf(stderr, "Error %s\n", strerror(errno));
                        return -1;
                }
 
                break;
        case SSH_KNOWN_HOSTS_ERROR:
                fprintf(stderr, "Error %s", ssh_get_error(session));
                ssh_clean_pubkey_hash(&hash);
                return -1;
        }
 
        ssh_clean_pubkey_hash(&hash);
        return 0;
}

void ssh_sftp_close(sftp_session sftp)
{
        ssh_session ssh = sftp_ssh(sftp);
        sftp_free(sftp);
        ssh_disconnect(ssh);
        ssh_free(ssh);
}
