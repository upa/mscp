====
MSCP
====

:Date:   v0.1.4-24-g426c3d6

NAME
====

mscp - copy files over multiple SSH connections

SYNOPSIS
========

**mscp** [**-46vqDpHdNh**] [ **-n**\ *NR_CONNECTIONS* ] [
**-m**\ *COREMASK* ] [ **-u**\ *MAX_STARTUPS* ] [ **-I**\ *INTERVAL* ] [
**-W**\ *CHECKPOINT* ] [ **-R**\ *CHECKPOINT* ] [
**-s**\ *MIN_CHUNK_SIZE* ] [ **-S**\ *MAX_CHUNK_SIZE* ] [
**-a**\ *NR_AHEAD* ] [ **-b**\ *BUF_SIZE* ] [ **-l**\ *LOGIN_NAME* ] [
**-P**\ *PORT* ] [ **-F**\ *CONFIG* ] [ **-i**\ *IDENTITY* ] [
**-c**\ *CIPHER* ] [ **-M**\ *HMAC* ] [ **-C**\ *COMPRESS* ] [
**-g**\ *CONGESTION* ] *source ... target*

DESCRIPTION
===========

**mscp** copies files over multiple SSH (SFTP) connections by multiple
threads. It enables transferring (1) multiple files simultaneously and
(2) a large file in parallel, reducing the transfer time for a lot
of/large files over networks.

The usage of **mscp** imitates the **scp** command of *OpenSSH,* for
example:

::

       $ mscp srcfile user@example.com:dstfile

Remote hosts only need to run standard **sshd** supporting the SFTP
subsystem, and users need to be able to **ssh** to the hosts as usual.
**mscp** does not require anything else.

**mscp** uses `libssh <https://www.libssh.org>`__ as its SSH
implementation. Thus, supported SSH features, for example,
authentication, encryption, and various options in ssh_config, follow
what *libssh* supports.

OPTIONS
=======

**-n NR_CONNECTIONS**
   Specifies the number of SSH connections. The default value is
   calculated from the number of CPU cores on the host with the
   following formula: floor(log(nr_cores)*2)+1.

**-m COREMASK**
   Configures CPU cores to be used by the hexadecimal bitmask. All CPU
   cores are used by default.

**-u MAX_STARTUPS**
   Specifies the number of concurrent outgoing SSH connections. **sshd**
   limits the number of simultaneous SSH connection attempts by
   *MaxStartups* in *sshd_config.* The default *MaxStartups* is 10;
   thus, we set the default MAX_STARTUPS 8.

**-I INTERVAL**
   Specifies the interval (in seconds) between SSH connection attempts.
   Some firewall products treat SSH connection attempts from a single
   source IP address for a short period as a brute force attack. This
   option inserts intervals between the attempts to avoid being
   determined as an attack. The default value is 0.

**-W CHECKPOINT**
   Specifies a checkpoint file to save the state of a failed transfer.
   When transferring fails due to, for example, connection disruption or
   user interrupt, **mscp** writes the information about the remaining
   files and chunks to the specified checkpoint file. **-W** option with
   **-D** (dry-run mode) only writes a checkpoint file and exits.

**-R CHECKPOINT**
   Specifies a checkpoint file to resume a transfer. When a checkpoint
   file is passed, **mscp** reads the checkpoint to load a remote host,
   copy direction, and files and their chunks to be transferred. Namely,
   **mscp** can resume a past failed transfer from the checkpoint.
   Resumeing with a checkpoint does not require *source ... target*
   arguments. Other SSH connection options, such as port number and
   config file, should be specified as with the failed run. In addition,
   checkpoint files have file paths as relative paths. Thus, you must
   run **mscp** in the same working directory as the failed run. You can
   see the contents of a checkpoint file with the **mscp -vv -D -R
   CHECKOPOINT** command (Dry-run mode). Note that the checkpoint file
   is not automatically removed after the resumed transfer ends
   successfully. Users should check the return value of **mscp** and
   remove the checkpoint if it returns 0.

**-s MIN_CHUNK_SIZE**
   Specifies the minimum chunk size. **mscp** divides a file into chunks
   and copies the chunks in parallel.

**-S MAX_CHUNK_SIZE**
   Specifies the maximum chunk size. The default is file size divided by
   the number of connections.

**-a NR_AHEAD**
   Specifies the number of inflight SFTP commands. The default value is
   32.

**-b BUF_SIZE**
   Specifies the buffer size for I/O and transfer over SFTP. The default
   value is 16384. Note that the SSH specification restricts buffer size
   delivered over SSH. Changing this value is not recommended at
   present.

**-4**
   Uses IPv4 addresses only.

**-6**
   Uses IPv6 addresses only.

**-v**
   Increments the verbose output level.

**-q**
   Quiet mode: turns off all outputs.

**-D**
   Dry-run mode: it scans source files to be copied, calculates chunks,
   and resolves destination file paths. Dry-run mode with **-vv** option
   enables confirming files to be copied and their destination paths.

**-r**
   No effect. **mscp** copies recursively if a source path is a
   directory. This option exists for just compatibility.

**-l LOGIN_NAME**
   Specifies the username to log in on the remote machine as with
   *ssh(1).*

**-P PORT**
   Specifies the port number to connect to on the remote machine as with
   ssh(1) and scp(1).

**-F CONFIG**
   Specifies an alternative per-user ssh configuration file. Note that
   acceptable options in the configuration file are what *libssh*
   supports.

**-i IDENTITY**
   Specifies the identity file for public key authentication.

**-c CIPHER**
   Selects the cipher to use for encrypting the data transfer. See
   `libssh features <https://www.libssh.org/features/>`__.

**-M HMAC**
   Specifies MAC hash algorithms. See `libssh
   features <https://www.libssh.org/features/>`__.

**-C COMPRESS**
   Enables compression: yes, no, zlib, zlib@openssh.com. The default is
   none. See `libssh features <https://www.libssh.org/features/>`__.

**-g CONGESTION**
   Specifies the TCP congestion control algorithm to use (Linux only).

**-p**
   Preserves modification times and access times (file mode bits are
   preserved by default).

**-H**
   Disables hostkey checking.

**-d**
   Increments the ssh debug output level.

**-N**
   Enables Nagle's algorithm. It is disabled by default.

**-h**
   Prints help.

EXIT STATUS
===========

Exit status is 0 on success, and >0 if an error occurs.

ENVIRONMENT
===========

**mscp** recognizes the following environment variables.

**MSCP_SSH_AUTH_PASSWORD**
   This environment variable passes a password for password
   authentication to establish SSH connections.

**MSCP_SSH_AUTH_PASSPHRASE**
   This environment variable passes a passphrase for public-key
   authentication for establishing SSH connections.

NOTES
=====

**mscp** uses glob(3) for globbing pathnames, including matching
patterns for local and remote paths. However, globbing on the *remote*
side does not work with musl libc (used in Alpine Linux and the
single-binary version of mscp) because musl libc does not support
GLOB_ALTDIRFUNC.

**mscp** does not support remote-to-remote copy, which **scp** supports.

EXAMPLES
========

Copy a local file to a remote host with different name:

::

       $ mscp ~/src-file 10.0.0.1:copied-file

Copy a local file and a directory to /tmp at a remote host:

::

       $ mscp ~/src-file dir1 10.0.0.1:/tmp

Save a checkpoint if transfer fails:

::

       $ mscp -W mscp.checkpoint many-large-files 10.0.0.1:dst/

Check the remaining files and chunkes, and resume the failed transfer:

::

       # Dump the content of a checkpoint and exit (dry-run mode)
       $ mscp -vv -D -R mscp.checkpoint

       # resume transferring from the checkpoint
       $ mscp -R mscp.checkpoint

In a long fat network, following options might improve performance:

::

       $ mscp -n 64 -m 0xffff -a 64 -c aes128-gcm@openssh.com src 10.0.0.1:

**-n** increases the number of SSH connections than default, **-m** pins
threads to specific CPU cores, **-a** increases asynchronous inflight
SFTP WRITE/READ commands, and **-c aes128-gcm@openssh.com** will be
faster than the default chacha20-poly1305 cipher, particularly on hosts
that support AES-NI.

SEE ALSO
========

**scp**\ (1), **ssh**\ (1), **sshd**\ (8).

PAPER REFERENCE
===============

Ryo Nakamura and Yohei Kuga. 2023. Multi-threaded scp: Easy and Fast
File Transfer over SSH. In Practice and Experience in Advanced Research
Computing (PEARC '23). Association for Computing Machinery, New York,
NY, USA, 320–323. `DOI <https://doi.org/10.1145/3569951.3597582>`__.

CONTACT INFROMATION
===================

For pathces, bug reports, or feature requests, please open an issue on
`GitHub <https://github.com/upa/mscp>`__.

AUTHORS
=======

Ryo Nakamura <upa@haeena.net>
