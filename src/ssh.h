#ifndef _SSH_H_
#define _SSH_H_

#include <stdbool.h>
#include "libssh/libssh.h"
#include "libssh/sftp.h"

#include <mscp.h>

/* ssh_init_sftp_session() creates sftp_session. sshdst accpets
 * user@hostname and hostname notations (by libssh).
 */
sftp_session ssh_init_sftp_session(const char *sshdst, struct mscp_ssh_opts *opts);
void ssh_sftp_close(sftp_session sftp);

#define sftp_ssh(sftp) (sftp)->session
#define sftp_get_ssh_error(sftp) ssh_get_error(sftp_ssh(sftp))

#endif /* _SSH_H_ */
