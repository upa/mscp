#ifndef _SSH_H_
#define _SSH_H_

#include <stdbool.h>
#include "libssh/libssh.h"
#include "libssh/sftp.h"


struct ssh_opts {
	char    *login_name;		/* -l */
	char    *port;			/* -p */
	char    *identity;		/* -i */
	char    *cipher;		/* -c */
	char	*hmac;			/* -M */
	int     compress;		/* -C */
	int     debuglevel;		/* -v */
	bool	no_hostkey_check;	/* -H */

#define PASSWORD_BUF_SZ	128
	char    *password;	/* password for password auth */
	char	*passphrase;	/* passphrase for private key  */
};

/* ssh_init_sftp_session() creates sftp_session. sshdst accpets
 * user@hostname and hostname notations (by libssh).
 */
sftp_session ssh_init_sftp_session(char *sshdst, struct ssh_opts *opts);
void ssh_sftp_close(sftp_session sftp);

#define sftp_ssh(sftp) (sftp)->session
#define sftp_get_ssh_error(sftp) ssh_get_error(sftp_ssh(sftp))

#endif /* _SSH_H_ */
