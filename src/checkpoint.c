
#include <fcntl.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include <path.h>
#include <print.h>
#include <platform.h>
#include <strerrno.h>
#include <openbsd-compat/openbsd-compat.h>

#include <checkpoint.h>

enum {
	OBJ_TYPE_META = 0x0A,
	OBJ_TYPE_PATH = 0x0B,
	OBJ_TYPE_CHUNK = 0x0C,
};

struct checkpoint_obj_hdr {
	uint8_t type;
	uint8_t rsv;
	uint16_t len; /* length of an object including this hdr */
} __attribute__((packed));

#define MSCP_CHECKPOINT_MAGIC 0x6d736370UL /* mscp in UTF-8 */
#define MSCP_CHECKPOINT_VERSION 0x1

struct checkpoint_obj_meta {
	struct checkpoint_obj_hdr hdr;

	uint32_t magic;
	uint8_t version;
	uint16_t reserved;
	uint8_t direction; /* L2R or R2L */

	char remote[0];
} __attribute__((packed));

struct checkpoint_obj_path {
	struct checkpoint_obj_hdr hdr;

	uint32_t idx;
	uint16_t src_off; /* offset to the src path
					 * string (including \0) from
					 * the head of this object. */

	uint16_t dst_off; /* offset to the dst path
					 * string (including \0) from
					 * the head of this object */
} __attribute__((packed));

#define obj_path_src(obj) ((char *)(obj) + ntohs(obj->src_off))
#define obj_path_dst(obj) ((char *)(obj) + ntohs(obj->dst_off))

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

int checkpoint_save(const char *pathname, int dir, char *remote, pool *path_pool,
		    pool *chunk_pool)
{
	struct checkpoint_obj_meta meta;
	struct iovec iov[2];
	struct chunk *c;
	struct path *p;
	unsigned int i, nr_paths, nr_chunks;
	int fd;

	fd = open(pathname, O_WRONLY | O_CREAT | O_TRUNC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
	if (fd < 0) {
		priv_set_errv("open: %s: %s", pathname, strerrno());
		return -1;
	}

	pr_notice("checkppoint: save to %s", pathname);

	/* write meta */
	memset(&meta, 0, sizeof(meta));
	meta.hdr.type = OBJ_TYPE_META;
	meta.hdr.len = htons(sizeof(meta) + strlen(remote) + 1);
	meta.magic = htonl(MSCP_CHECKPOINT_MAGIC);
	meta.version = MSCP_CHECKPOINT_VERSION;
	meta.direction = dir;

	iov[0].iov_base = &meta;
	iov[0].iov_len = sizeof(meta);
	iov[1].iov_base = remote;
	iov[1].iov_len = strlen(remote) + 1;

	if (writev(fd, iov, 2) < 0) {
		priv_set_errv("writev: %s", strerrno());
		return -1;
	}

	/* write paths */
	nr_paths = 0;
	pool_for_each(path_pool, p, i) {
		if (p->state == FILE_STATE_DONE)
			continue;
		if (checkpoint_write_path(fd, p, i) < 0)
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

	pr_info("checkpoint: %u paths and %u chunks saved", nr_paths, nr_chunks);

	return 0;
}

static int checkpoint_load_meta(struct checkpoint_obj_hdr *hdr, char *remote, size_t len,
				int *dir)
{
	struct checkpoint_obj_meta *meta = (struct checkpoint_obj_meta *)hdr;

	if (ntohl(meta->magic) != MSCP_CHECKPOINT_MAGIC) {
		priv_set_errv("checkpoint: invalid megic code");
		return -1;
	}

	if (meta->version != MSCP_CHECKPOINT_VERSION) {
		priv_set_errv("checkpoint: unknown version %u", meta->version);
		return -1;
	}
	pr_debug("checkpoint: version %u", meta->version);

	if (len < ntohs(hdr->len) - sizeof(*meta)) {
		priv_set_errv("too short buffer");
		return -1;
	}
	snprintf(remote, len, "%s", meta->remote);
	*dir = meta->direction;

	pr_notice("checkpoint: loaded, remote=%s direction=%s", meta->remote,
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

	if (!(s = strdup(obj_path_src(path)))) {
		priv_set_errv("strdup: %s", strerrno());
		return -1;
	}

	if (!(d = strdup(obj_path_dst(path)))) {
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

	pr_info("checkpoint: %s -> %s", p->path, p->dst_path);

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

	pr_debug("checkpoint: %s 0x%lx-0x%lx", p->path, c->off, c->off + c->len);

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
