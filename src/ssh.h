#ifndef _SSH_H_
#define _SSH_H_

#include <libssh/libssh.h>
#include <libssh/sftp.h>


struct ssh_opts {
        char    *login_name;    /* -l */
        char    *port;          /* -p */
        char    *identity;      /* -i */
        char    *cipher;        /* -c */
        int     compress;       /* -C */
        int     debuglevel;     /* -v */

        char    *password;      /* filled at the first connecting phase */
};

/* ssh_make_sftp_session() creates sftp_session. sshdst accpets
 * user@hostname and hostname notations (by libssh).
 */
sftp_session ssh_make_sftp_session(char *sshdst, struct ssh_opts *opts);
void ssh_sftp_close(sftp_session sftp);

#define sftp_ssh(sftp) (sftp)->session

#endif /* _SSH_H_ */
