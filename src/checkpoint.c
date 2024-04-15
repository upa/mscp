/* SPDX-License-Identifier: GPL-3.0-only */
#include <fcntl.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <path.h>
#include <print.h>
#include <platform.h>
#include <strerrno.h>
#include <openbsd-compat/openbsd-compat.h>

#include <checkpoint.h>

#define MSCP_CHECKPOINT_MAGIC 0x7063736dUL /* mscp in ascii */
#define MSCP_CHECKPOINT_VERSION 0x1

/**
 * mscp checkpoint file format. All values are network byte order.
 *
 * The file starts with the File header:
 * 0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +---------------------------------------------------------------+
 * |                          Magic Code                           |
 * +---------------+-----------------------------------------------+
 * |     Version   |
 * +---------------+
 *
 * Magic code: 0x7063736dUL
 *
 * Version: 1.
 *
 *
 * Each object in a checkpoint always starts with an object header:
 * +---------------+---------------+-------------------------------+
 * |     Type      |      rsv      |             Length            |
 * +---------------+---------------+-------------------------------+
 *
 * Type: 0x0A (meta), 0x0B (path), or 0x0C (chunk)
 *
 * Rsv: reserved
 *
 * Length: Length of this object including the object header.
 *
 *
 * Meta object provides generaic information for the failed copy:
 * +---------------+---------------+-------------------------------+
 * |     Type      |      rsv      |             Length            |
 * +---------------+---------------+-------------------------------+
 * |  Direction    | Remote string ...
 * +---------------+------------------
 *
 * Direction: 1 (Local-to-Remote copy) or 2 (Remote-to-Local copy)
 *
 * Remote string: Remote host, e.g., user@hostname and IP address,
 * string including '\0'.
 *
 *
 * Path object represnts a file with sourcen and destination paths:
 * +---------------+---------------+-------------------------------+
 * |     Type      |      rsv      |             Length            |
 * +---------------+---------------+-------------------------------+
 * |                             Index                             |
 * +-------------------------------+-------------------------------+
 * |         Source offset         |      Destination offset       |
 * +-------------------------------+-------------------------------+
 * //                                                             //
 * //                     Source path string                      //
 * //                                                             //
 * +---------------------------------------------------------------+
 * //                                                             //
 * //                   Destination path string                   //
 * //                                                             //
 * +---------------------------------------------------------------+
 *
 * Index: 32-bit unsigned int indicating this path (used by chunks)
 *
 * Source offset: Offset of the Source path string from the head of
 * this object. It is identical to the end of the Destination offset
 * filed.
 *
 * Destination offset: Offset of the Destnation path string from the
 * head of this object. It also indicates the end of the Source path
 * string.
 *
 * Source path string: String of copy source path (including '\0').
 *
 * Destination path string: string of copy destination path (including
 * '\0').
 *
 *
 * Chunk object represents a chunk associated with a path object:
 * +---------------+---------------+-------------------------------+
 * |     Type      |      rsv      |             Length            |
 * +---------------+---------------+-------------------------------+
 * |                             Index                             |
 * +---------------------------------------------------------------+
 * |                             Chunk                             |
 * |                             offset                            |
 * +---------------------------------------------------------------+
 * |                             Chunk                             |
 * |                             length                            |
 * +---------------------------------------------------------------+
 *
 * Index: 32 bit unsigned int indicating the index of a path object
 * this chunk associated with.
 *
 * Chunk offset: 64 bit unsigned int indicating the offset of this
 * chunk from the head of the associating a file.
 *
 * Chunk length: 64 bit unsigned int indicating the length (bytes) of
 * this chunk.
 */

enum {
	OBJ_TYPE_META = 0x0A,
	OBJ_TYPE_PATH = 0x0B,
	OBJ_TYPE_CHUNK = 0x0C,
};

struct checkpoint_file_hdr {
	uint32_t magic;
	uint8_t version;
} __attribute__((packed));

struct checkpoint_obj_hdr {
	uint8_t type;
	uint8_t rsv;
	uint16_t len; /* length of an object including this hdr */
} __attribute__((packed));

struct checkpoint_obj_meta {
	struct checkpoint_obj_hdr hdr;
	uint8_t direction; /* L2R or R2L */

	char remote[0];
} __attribute__((packed));

struct checkpoint_obj_path {
	struct checkpoint_obj_hdr hdr;

	uint32_t idx;
	uint16_t src_off; /* offset to the src path string (including
			   * \0) from the head of this object. */
	uint16_t dst_off; /* offset to the dst path string (including
			   * \0) from the head of this object */
} __attribute__((packed));

#define obj_path_src(o) ((char *)(o) + ntohs(o->src_off))
#define obj_path_dst(o) ((char *)(o) + ntohs(o->dst_off))

#define obj_path_src_len(o) (ntohs(o->dst_off) - ntohs(o->src_off))
#define obj_path_dst_len(o) (ntohs(o->hdr.len) - ntohs(o->dst_off))

#define obj_path_validate(o)				\
	((ntohs(o->hdr.len) > ntohs(o->dst_off)) &&	\
	 (ntohs(o->dst_off) > ntohs(o->src_off)) &&	\
	 (obj_path_src_len(o) < PATH_MAX) &&		\
	 (obj_path_dst_len(o) < PATH_MAX))

struct checkpoint_obj_chunk {
	struct checkpoint_obj_hdr hdr;

	uint32_t idx; /* index indicating associating path */
	uint64_t off;
	uint64_t len;
} __attribute__((packed));

#define CHECKPOINT_OBJ_MAXLEN (sizeof(struct checkpoint_obj_path) + PATH_MAX * 2)

static int checkpoint_write_path(int fd, struct path *p, unsigned int idx)
{
	char buf[CHECKPOINT_OBJ_MAXLEN];
	struct checkpoint_obj_path *path = (struct checkpoint_obj_path *)buf;
	size_t src_len, dst_len;
	struct iovec iov[3];

	p->data = idx; /* save idx to be pointed by chunks */

	src_len = strlen(p->path) + 1;
	dst_len = strlen(p->dst_path) + 1;

	memset(buf, 0, sizeof(buf));
	path->hdr.type = OBJ_TYPE_PATH;
	path->hdr.len = htons(sizeof(*path) + src_len + dst_len);

	path->idx = htonl(idx);
	path->src_off = htons(sizeof(*path));
	path->dst_off = htons(sizeof(*path) + src_len);

	iov[0].iov_base = path;
	iov[0].iov_len = sizeof(*path);
	iov[1].iov_base = p->path;
	iov[1].iov_len = src_len;
	iov[2].iov_base = p->dst_path;
	iov[2].iov_len = dst_len;

	if (writev(fd, iov, 3) < 0) {
		priv_set_errv("writev: %s", strerrno());
		return -1;
	}
	return 0;
}

static int checkpoint_write_chunk(int fd, struct chunk *c)
{
	struct checkpoint_obj_chunk chunk;

	memset(&chunk, 0, sizeof(chunk));
	chunk.hdr.type = OBJ_TYPE_CHUNK;
	chunk.hdr.len = htons(sizeof(chunk));

	chunk.idx = htonl(c->p->data); /* index stored by checkpoint_write_path */
	chunk.off = htonll(c->off);
	chunk.len = htonll(c->len);

	if (write(fd, &chunk, sizeof(chunk)) < 0) {
		priv_set_errv("writev: %s", strerrno());
		return -1;
	}
	return 0;
}

int checkpoint_save(const char *pathname, int dir, const char *user, const char *remote,
		    pool *path_pool, pool *chunk_pool)
{
	struct checkpoint_file_hdr hdr;
	struct checkpoint_obj_meta meta;
	struct iovec iov[3];
	struct chunk *c;
	struct path *p;
	char buf[1024];
	unsigned int i, nr_paths, nr_chunks;
	int fd, ret;

	fd = open(pathname, O_WRONLY | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (fd < 0) {
		priv_set_errv("open: %s: %s", pathname, strerrno());
		return -1;
	}

	/* write file hdr */
	hdr.magic = htonl(MSCP_CHECKPOINT_MAGIC);
	hdr.version = MSCP_CHECKPOINT_VERSION;

	/* write meta */
	if (user)
		ret = snprintf(buf, sizeof(buf), "%s@%s", user, remote);
	else
		ret = snprintf(buf, sizeof(buf), "%s", remote);
	if (ret >= sizeof(buf)) {
		priv_set_errv("too long username and/or remote");
		return -1;
	}

	memset(&meta, 0, sizeof(meta));
	meta.hdr.type = OBJ_TYPE_META;
	meta.hdr.len = htons(sizeof(meta) + strlen(buf) + 1);
	meta.direction = dir;

	iov[0].iov_base = &hdr;
	iov[0].iov_len = sizeof(hdr);
	iov[1].iov_base = &meta;
	iov[1].iov_len = sizeof(meta);
	iov[2].iov_base = buf;
	iov[2].iov_len = strlen(buf) + 1;

	if (writev(fd, iov, 3) < 0) {
		priv_set_errv("writev: %s", strerrno());
		return -1;
	}

	/* write paths */
	nr_paths = 0;
	pool_for_each(path_pool, p, i) {
		if (p->state == FILE_STATE_DONE)
			continue;
		if (checkpoint_write_path(fd, p, nr_paths) < 0)
			return -1;
		nr_paths++;
	}

	/* write chunks */
	nr_chunks = 0;
	pool_for_each(chunk_pool, c, i) {
		if (c->state == CHUNK_STATE_DONE)
			continue;
		if (checkpoint_write_chunk(fd, c) < 0)
			return -1;
		nr_chunks++;
	}

	pr_notice("checkpoint: %u paths and %u chunks saved", nr_paths, nr_chunks);

	return 0;
}

static int checkpoint_load_meta(struct checkpoint_obj_hdr *hdr, char *remote, size_t len,
				int *dir)
{
	struct checkpoint_obj_meta *meta = (struct checkpoint_obj_meta *)hdr;

	if (len < ntohs(hdr->len) - sizeof(*meta)) {
		priv_set_errv("too short buffer");
		return -1;
	}
	snprintf(remote, len, "%s", meta->remote);
	*dir = meta->direction;

	pr_notice("checkpoint: remote=%s direction=%s", meta->remote,
		  meta->direction == MSCP_DIRECTION_L2R ? "local-to-remote" :
		  meta->direction == MSCP_DIRECTION_R2L ? "remote-to-local" :
							  "invalid");

	return 0;
}

static int checkpoint_load_path(struct checkpoint_obj_hdr *hdr, pool *path_pool)
{
	struct checkpoint_obj_path *path = (struct checkpoint_obj_path *)hdr;
	struct path *p;
	char *s, *d;

	if (!obj_path_validate(path)) {
		priv_set_errv("invalid path object");
		return -1;
	}

	if (!(s = strndup(obj_path_src(path), obj_path_src_len(path)))) {
		priv_set_errv("strdup: %s", strerrno());
		return -1;
	}

	if (!(d = strndup(obj_path_dst(path), obj_path_dst_len(path)))) {
		priv_set_errv("strdup: %s", strerrno());
		free(s);
		return -1;
	}

	if (!(p = alloc_path(s, d))) {
		free(s);
		free(d);
		return -1;
	}

	if (pool_push(path_pool, p) < 0) {
		priv_set_errv("pool_push: %s", strerrno());
		return -1;
	}

	pr_info("checkpoint:file: idx=%u %s -> %s", ntohl(path->idx),
		p->path, p->dst_path);

	return 0;
}

static int checkpoint_load_chunk(struct checkpoint_obj_hdr *hdr, pool *path_pool,
				 pool *chunk_pool)
{
	struct checkpoint_obj_chunk *chunk = (struct checkpoint_obj_chunk *)hdr;
	struct chunk *c;
	struct path *p;

	if (!(p = pool_get(path_pool, ntohl(chunk->idx)))) {
		/* we assumes all paths are already loaded in the order */
		priv_set_errv("path index %u not found", ntohl(chunk->idx));
		return -1;
	}

	if (!(c = alloc_chunk(p, ntohll(chunk->off), ntohll(chunk->len))))
		return -1;

	if (pool_push(chunk_pool, c) < 0) {
		priv_set_errv("pool_push: %s", strerrno());
		return -1;
	}

	pr_debug("checkpoint:chunk: idx=%u %s 0x%lx-0x%lx", ntohl(chunk->idx),
		 p->path, c->off, c->off + c->len);

	return 0;
}

static int checkpoint_read_obj(int fd, void *buf, size_t count)
{
	struct checkpoint_obj_hdr *hdr = (struct checkpoint_obj_hdr *)buf;
	ssize_t ret, objlen, objbuflen;

	memset(buf, 0, count);

	if (count < sizeof(*hdr)) {
		priv_set_errv("too short buffer");
		return -1;
	}

	ret = read(fd, hdr, sizeof(*hdr));
	if (ret == 0)
		return 0; /* no more objects */
	if (ret < 0)
		return -1;

	objlen = ntohs(hdr->len) - sizeof(*hdr);
	objbuflen = count - sizeof(*hdr);
	if (objbuflen < objlen) {
		priv_set_errv("too short buffer");
		return -1;
	}

	ret = read(fd, buf + sizeof(*hdr), objlen);
	if (ret < objlen) {
		priv_set_errv("checkpoint truncated");
		return -1;
	}

	return 1;
}

static int checkpoint_read_file_hdr(int fd)
{
	struct checkpoint_file_hdr hdr;
	ssize_t ret;

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret < 0) {
		priv_set_errv("read: %s", strerrno());
		return -1;
	}
	if (ret < sizeof(hdr)) {
		priv_set_errv("checkpoint truncated");
		return -1;
	}

	if (ntohl(hdr.magic) != MSCP_CHECKPOINT_MAGIC) {
		priv_set_errv("checkpoint: invalid megic code");
		return -1;
	}

	if (hdr.version != MSCP_CHECKPOINT_VERSION) {
		priv_set_errv("checkpoint: unknown version %u", hdr.version);
		return -1;
	}

	return 0;
}

static int checkpoint_load(const char *pathname, char *remote, size_t len, int *dir,
			   pool *path_pool, pool *chunk_pool)
{
	char buf[CHECKPOINT_OBJ_MAXLEN];
	struct checkpoint_obj_hdr *hdr;
	int fd, ret;

	if ((fd = open(pathname, O_RDONLY)) < 0) {
		priv_set_errv("open: %s: %s", pathname, strerrno());
		return -1;
	}

	if (checkpoint_read_file_hdr(fd) < 0)
		return -1;

	hdr = (struct checkpoint_obj_hdr *)buf;
	while ((ret = checkpoint_read_obj(fd, buf, sizeof(buf))) > 0) {
		switch (hdr->type) {
		case OBJ_TYPE_META:
			if (!remote || !dir)
				break;
			if (checkpoint_load_meta(hdr, remote, len, dir) < 0)
				return -1;
			if (!path_pool || !chunk_pool)
				goto out;
			break;
		case OBJ_TYPE_PATH:
			if (!path_pool)
				break;
			if (checkpoint_load_path(hdr, path_pool) < 0)
				return -1;
			break;
		case OBJ_TYPE_CHUNK:
			if (!path_pool)
				break;
			if (checkpoint_load_chunk(hdr, path_pool, chunk_pool) < 0)
				return -1;
			break;
		default:
			priv_set_errv("unknown obj type %u", hdr->type);
			return -1;
		}
	}

out:
	close(fd);

	return 0;
}

int checkpoint_load_remote(const char *pathname, char *remote, size_t len, int *dir)
{
	return checkpoint_load(pathname, remote, len, dir, NULL, NULL);
}

int checkpoint_load_paths(const char *pathname, pool *path_pool, pool *chunk_pool)
{
	return checkpoint_load(pathname, NULL, 0, NULL, path_pool, chunk_pool);
}
