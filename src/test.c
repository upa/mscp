#include <util.h>
#include <path.h>

int path_walk_test(int argc, char **argv)
{
	struct list_head path_list, chunk_list, tmp;
	mstat src, dst;
	bool dst_is_dir = false, src_is_dir = false;
	int ret, n;

	
	if (mscp_stat(argv[argc - 1], &dst, NULL) == 0) {
		if (mstat_is_dir(dst))
			dst_is_dir = true;
	}

	INIT_LIST_HEAD(&path_list);
	INIT_LIST_HEAD(&chunk_list);

	for (n = 1; n < argc - 1; n++) {
		if (mscp_stat(argv[n], &src, NULL) < 0) {
			pr_err("%s not found: %s\n", argv[n], strerrno());
			return -1;
		}
		src_is_dir = mstat_is_dir(src);

		INIT_LIST_HEAD(&tmp);
		ret = walk_src_path(NULL, argv[n], &tmp);
		if (ret < 0)
			return ret;

		ret = resolve_dst_path(NULL, argv[n], argv[argc - 1], &tmp,
				       mstat_is_dir(src), dst_is_dir);
		if (ret < 0)
			return ret;

		list_splice_tail(&tmp, &path_list);
	}

	path_dump(&path_list);

	ret = prepare_chunk(&path_list, &chunk_list, 4, 1024 * 1024, 0);
	if (ret < 0)
		return ret;

	//chunk_dump(&chunk_list);


	return 0;
}

void usage()
{
	printf("test [SRC_PATH] ... [DST_PATH]\n");
}

int main(int argc, char **argv)
{
	if (argc < 3) {
		usage();
		return 1;
	}

	if (path_walk_test(argc, argv) < 0)
		return 1;

	return 0;
}
