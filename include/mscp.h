#ifndef _MSCP_H_
#define _MSCP_H_

/**
 * @file mscp.h
 *
 * @brief mscp library header file.
 *
 * @mainpage
 *
 * libmscp is a library for multi-threaded scp. Project page is
 * https://github.com/upa/mscp.
 *
 * All public APIs of libmscp are defined in mscp.h. Basic usage of
 * libmscp is follows:
 *
 * 1. create mscp instance with mscp_init()
 * 2. connect to remote host with mscp_connect()
 * 3. add path to source files with mscp_add_src_path()
 * 4. set path to destination with mscp_set_dst_path()
 * 5. finish preparation with mscp_prepare()
 * 6. start copy with mscp_start()
 * 7. wait for copy finished with mscp_join()
 * 8. cleanup mscp instance with mscp_cleanup() and mscp_free()
 */

#include <stdbool.h>
#include <limits.h>

#define MSCP_DIRECTION_L2R	1	/** Indicates local to remote copy */
#define MSCP_DIRECTION_R2L	2	/** Indicates remote to local copy */

#define MSCP_MAX_COREMASK_STR	64

/**
 * @struct	mscp_opts
 * @brief	Structure configuring mscp.
 */
struct mscp_opts {
	int	nr_threads;	/** number of copy threads */
	int	nr_ahead;	/** number of SFTP commands on-the-fly */
	size_t	min_chunk_sz;	/** minimum chunk size (default 64MB) */
	size_t	max_chunk_sz;	/** maximum chunk size (default file size/nr_threads) */
	size_t	buf_sz;		/** buffer size, default 16k. */
	char	coremask[MSCP_MAX_COREMASK_STR]; /** hex to specifiy usable cpu cores */

	int	severity; 	/** messaging severity. set MSCP_SERVERITY_* */
	int	msg_fd;		/** fd to output message. default STDOUT (0),
				 * and -1 disables output */
};

#define MSCP_SSH_MAX_LOGIN_NAME		64
#define MSCP_SSH_MAX_PORT_STR		32
#define MSCP_SSH_MAX_IDENTITY_PATH	PATH_MAX
#define MSCP_SSH_MAX_CIPHER_STR		32
#define MSCP_SSH_MAX_HMAC_STR		32
#define MSCP_SSH_MAX_COMP_STR		32 /* yes, no, zlib, zlib@openssh.com, none */
#define MSCP_SSH_MAX_PASSWORD		128
#define MSCP_SSH_MAX_PASSPHRASE		128

/**
 * @struct	mscp_ssh_opts
 * @brief	Structure configuring SSH connections
 */
struct mscp_ssh_opts {
	/* ssh options */
	char	login_name[MSCP_SSH_MAX_LOGIN_NAME];	/** ssh username */
	char	port[MSCP_SSH_MAX_PORT_STR];		/** ssh port */
	char	identity[MSCP_SSH_MAX_IDENTITY_PATH];	/** path to private key */
	char	cipher[MSCP_SSH_MAX_CIPHER_STR];	/** cipher spec */
	char	hmac[MSCP_SSH_MAX_HMAC_STR];		/** hmacp spec */
	char	compress[MSCP_SSH_MAX_COMP_STR];	/** yes, no, zlib@openssh.com */

	char	password[MSCP_SSH_MAX_PASSWORD];	/** password auth passowrd */
	char	passphrase[MSCP_SSH_MAX_PASSPHRASE];	/** passphrase for private key */

	int	debug_level;		/** inclirement libssh debug output level */
	bool	no_hostkey_check;	/** do not check host keys */
	bool	enable_nagle;		/** enable Nagle's algorithm if true */
};

/**
 * @struct	mscp_stats
 * @brief	Structure to get mscp statistics
 */
struct mscp_stats {
	size_t total;	/** total bytes to be transferred */
	size_t done;	/** total bytes transferred */
	bool finished;	/** true when all copy threads finished */
};


/** Structure representing mscp instance */
struct mscp;

/**
 * @brief Creates a new mscp instance.
 *
 * @param remote_host	remote host for file transer.
 * @param direction	copy direction, `MSCP_DIRECTION_L2R` or `MSCP_DIRECTION_R2L`
 * @param o		options for configuring mscp.
 * @param s		options for configuring ssh connections.
 *
 * @retrun 		A new mscp instance or NULL on error.
 */
struct mscp *mscp_init(const char *remote_host, int direction,
		       struct mscp_opts *o, struct mscp_ssh_opts *s);

/**
 * @brief Connect the first SSH connection. mscp_connect connects to
 * remote host and initialize a SFTP session over the
 * connection. mscp_prepare() and mscp_start() require mscp_connect()
 * beforehand.
 *
 * @param m	mscp instance.
 *
 * @return 	0 on success, < 0 if an error occured.
 *              mscp_get_error() can be used to retrieve error message.
 */
int mscp_connect(struct mscp *m);

/* add a source file path to be copied */

/**
 * @brief Add a source file path to be copied. The path indicates
 * either a file or directory. The path can be `user@host:path`
 * notation.  In this case, `dst_path` for mscp_set_dst_path() must
 * not contain remote host notation.
 *
 * @param m		mscp instance.
 * @param src_path	source file path to be copied.
 *
 * @return 		0 on success, < 0 if an error occured.
 *              	mscp_get_error() can be used to retrieve error message.
 */
int mscp_add_src_path(struct mscp *m, const char *src_path);

/**
 * @brief Set the destination file path. The path indicates either a
 * file, directory, or nonexistent path. The path can be
 * `user@host:path` notation.  In this case, all source paths appended
 * by mscp_set_src_path() must not contain remote host notation.
 *
 * @param m		mscp instance.
 * @param dst_path	destination path to which source files copied.
 *
 * @return 		0 on success, < 0 if an error occured.
 *              	mscp_get_error() can be used to retrieve error message.
 */
int mscp_set_dst_path(struct mscp *m, const char *dst_path);

/* check source files, resolve destination file paths for all source
 * files, and prepare chunks for all files. */

/**
 * @brief Prepare for file transfer. This function checks all source
 * files (recursively), resolve paths on the destination side, and
 * calculate file chunks.
 *
 * @param m	mscp instance.
 *
 * @return 	0 on success, < 0 if an error occured.
 *              mscp_get_error() can be used to retrieve error message.
 */
int mscp_prepare(struct mscp *m);

/**
 * @brief Start to copy files. mscp_start() returns immediately. You
 * can get statistics via mscp_get_stats() or messages via pipe set by
 * mscp_opts.msg_fd or mscp_set_msg_fd(). mscp_stop() cancels mscp
 * copy threads, and mscp_join() joins the threads.
 *
 * @param m	mscp instance.
 *
 * @return 	0 on success, < 0 if an error occured.
 *              mscp_get_error() can be used to retrieve error message.
 *
 * @see		mscp_join()
 */
int mscp_start(struct mscp *m);


/**
 * @brief Stop coping files.
 *
 * @param m	mscp instance.
 */
void mscp_stop(struct mscp *m);


/**
 * @brief Join copy threads. This function is blocking until all copy
 * have done.
 *
 * @param m	mscp instance.
 *
 * @return 	0 on success, < 0 if an error occured.
 *              mscp_get_error() can be used to retrieve error message.
 */
int mscp_join(struct mscp *m);

/**
 * @brief Get statistics of copy.
 *
 * @param m		mscp instance.
 * @param s[out]	statistics.
 */
void mscp_get_stats(struct mscp *m, struct mscp_stats *s);

/**
 * @brief Cleanup the mscp instance. Before calling mscp_cleanup(), must
 * call mscp_join(). After mscp_cleanup() called, the mscp instance
 * can restart from mscp_connect().
 *
 * @param m		mscp instance.
 */
void mscp_cleanup(struct mscp *m);

/**
 * @brief Release the mscp instance.
 *
 * @param m		mscp instance.
 */
void mscp_free(struct mscp *m);


/* messaging with mscp */

/**
 * @enum	mscp_serverity
 * @brief 	Filter messages from libmscp with severity level.
 */
enum {
	MSCP_SEVERITY_NONE	= -1,
	MSCP_SEVERITY_ERR	= 0,
	MSCP_SEVERITY_WARN	= 1,
	MSCP_SEVERITY_NOTICE	= 2,
        MSCP_SEVERITY_INFO	= 3,
	MSCP_SEVERITY_DEBUG	= 4,
};


/**
 * @brief Set a file descriptor for receiving messages from mscp.
 * This function has the same effect with setting mscp_opts->msg_fd.
 *
 * @param m	mscp instance.
 * @param fd	fd to which libmscp writes messages.
 */
void mscp_set_msg_fd(struct mscp *m, int fd);


/**
 * @brief Get the recent error message from libmscp. Note that this
 * function is not thread-safe.
 *
 * @return 	pointer to the message.
 */
const char *mscp_get_error(void);



#endif /* _MSCP_H_ */
