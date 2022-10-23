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

/* wrapping multiple sftp_read|write */
int sftp_write2(sftp_file sf, const void *buf, size_t len, size_t sftp_buf_sz);
int sftp_read2(sftp_file sf, void *buf, size_t len, size_t sftp_buf_sz);

#endif /* _SSH_H_ */
