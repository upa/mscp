
"""
test_e2e.py: End-to-End test for mscp executable.
"""

import pytest
import os

from subprocess import check_call, CalledProcessError, PIPE
from util import File, check_same_md5sum


def run2ok(args):
    check_call(list(map(str, args)))

def run2ng(args):
    with pytest.raises(CalledProcessError) as e:
        check_call(list(map(str, args)))


""" usage test """

def test_usage(mscp):
    run2ng([mscp])
    run2ok([mscp, "-h"])

def test_invalid_chunk_size_config(mscp):
    run2ng([mscp, "-s", 8 << 20, "-S", 4 << 20])

param_invalid_hostnames = [
    (["a:a", "b:b", "c:c"]), (["a:a", "b:b", "c"]), (["a:a", "b", "c:c"]),
    (["a", "b:b", "c:c"])
]

@pytest.mark.parametrize("args", param_invalid_hostnames)
def test_nonidentical_hostnames(mscp, args):
    run2ng([mscp] + args)




""" copy test """

remote_prefix = "localhost:{}/".format(os.getcwd()) # use current dir
param_remote_prefix = [
    ("", remote_prefix), (remote_prefix, "")
]

param_single_copy = [
    (File("src", size = 64), File("dst")),
    (File("src", size = 4096 * 1), File("dst")),
    (File("src", size = 128 * 1024 * 1024), File("dst")),
]

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("src, dst", param_single_copy)
def test_single_copy(mscp, src_prefix, dst_prefix, src, dst):
    src.make()
    run2ok([mscp, "-H", "-vvv", src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_failed_to_copy_nonexistent_file(mscp, src_prefix, dst_prefix):
    src = "nonexistent_src"
    dst = "nonexistent_dst"
    run2ng([mscp, "-H", "-vvv", src_prefix + src, dst_prefix + dst])

param_double_copy = [
    (File("src1", size = 1024 * 1024), File("src2", size = 1024 * 1024),
     File("dst/src1"), File("dst/src2")
     )
]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("s1, s2, d1, d2", param_double_copy)
def test_double_copy(mscp, src_prefix, dst_prefix, s1, s2, d1, d2):
    s1.make()
    s2.make()
    run2ok([mscp, "-H", "-vvv", src_prefix + s1.path, src_prefix + s2.path, dst_prefix + "dst"])
    assert check_same_md5sum(s1, d1)
    assert check_same_md5sum(s2, d2)
    s1.cleanup()
    s2.cleanup()
    d1.cleanup()
    d2.cleanup()

param_dir_copy = [
    ( "src_dir", "dst_dir",
        [ File("src_dir/t1", size = 64),
          File("src_dir/t2", size = 4096),
          File("src_dir/d1/t3", size = 64),
          File("src_dir/d1/d2/t4", size = 128), ],
        [ File("dst_dir/t1"),
          File("dst_dir/t2"),
          File("dst_dir/d1/t3"),
          File("dst_dir/d1/d2/t4"), ],
        [ File("dst_dir/src_dir/t1"),
          File("dst_dir/src_dir/t2"),
          File("dst_dir/src_dir/d1/t3"),
          File("dst_dir/src_dir/d1/d2/t4"), ],
    )
]

"""
`scp remote:src_dir dst_dir` renames src_dir to dst_dir if dst_dir
does not exist. If dst_dir exists, scp copies src_dir to
dst_dir/src_dir. So, this test checks both cases.
"""

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("src_dir, dst_dir, src, dst, twice", param_dir_copy)
def test_dir_copy(mscp, src_prefix, dst_prefix, src_dir, dst_dir, src, dst, twice):
    for f in src:
        f.make()

    run2ok([mscp, "-H", "-vvv", src_prefix + src_dir, dst_prefix + dst_dir])
    for sf, df in zip(src, dst):
        assert check_same_md5sum(sf, df)

    run2ok([mscp, "-H", "-vvv", src_prefix + src_dir, dst_prefix + dst_dir])
    for sf, df in zip(src, twice):
        assert check_same_md5sum(sf, df)

    for sf, df, tf in zip(src, dst, twice):
        sf.cleanup()
        df.cleanup()
        tf.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_override_single_file(mscp, src_prefix, dst_prefix):
    src = File("src", size = 128).make()
    dst = File("dst", size = 128).make()
    assert not check_same_md5sum(src, dst)

    run2ok([mscp, "-H", "-vvv", src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)

    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_min_chunk(mscp, src_prefix, dst_prefix):
    src = File("src", size = 16 * 1024).make()
    dst = File("dst")

    run2ok([mscp, "-H", "-vvv", "-s", 32768, src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)

    src.cleanup()
    dst.cleanup()


def is_alpine():
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release", "r") as f:
            for line in f:
                if line.strip() == "ID=alpine":
                    return True
    return False

param_glob_copy = [
    (
        "src*", "dstx",
        [ File("src1"), File("src2"), File("src3") ],
        [ File("dstx/src1"), File("dstx/src2"), File("dstx/src3") ],
    ),
    (
        "src*", "dstx",
        [ File("src1/s1"), File("src2/s2"), File("src3/s3") ],
        [ File("dstx/s1"), File("dstx/s2"), File("dstx/s3") ],
    )
]

@pytest.mark.skipif(is_alpine(),
                    reason = "musl does not implement glob ALTDIRFUNC")
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("src_glob_path, dst_path, srcs, dsts", param_glob_copy)
def test_glob_src_path(mscp, src_prefix, dst_prefix,
                       src_glob_path, dst_path, srcs, dsts):
    for src in srcs:
        src.make(size = 1024 * 1024)

    run2ok([mscp, "-H", "-vvv", src_prefix + src_glob_path, dst_prefix + dst_path])
    for src, dst in zip(srcs, dsts):
        assert check_same_md5sum(src, dst)
        src.cleanup()
        dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_thread_affinity(mscp, src_prefix, dst_prefix):
    src = File("src", size = 64 * 1024).make()
    dst = File("dst")

    run2ok([mscp, "-H", "-vvv", "-n", 4, "-m", "0x01",
            src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)

    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_cannot_override_file_with_dir(mscp, src_prefix, dst_prefix):
    src = File("src", size = 128).make()
    dst = File("dst").make()

    run2ng([mscp, "-H", "-vvv", src_prefix + src.path, dst_prefix + "dst/src"])

    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_transfer_zero_bytes(mscp, src_prefix, dst_prefix):
    src = File("src", size = 0).make()
    dst = File("dst")
    run2ok([mscp, "-H", "-vvv", src_prefix + src.path, dst_prefix + "dst"])
    assert os.path.exists("dst")
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_override_dst_having_larger_size(mscp, src_prefix, dst_prefix):
    src = File("src", size = 1024 * 1024).make()
    dst = File("dst", size = 1024 * 1024 * 2).make()
    run2ok([mscp, "-H", "-vvv", src_prefix + src.path, dst_prefix + "dst"])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_dont_truncate_dst(mscp, src_prefix, dst_prefix):
    f = File("srcanddst", size = 1024 * 1024 * 128).make()
    md5_before = f.md5sum()
    run2ok([mscp, "-H", "-vvv", src_prefix + f.path, dst_prefix + f.path])
    md5_after = f.md5sum()
    assert md5_before == md5_after
    f.cleanup()

compressions = ["yes", "no", "none"]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("compress", compressions)
def test_compression(mscp, src_prefix, dst_prefix, compress):
    src = File("src", size = 1024 * 1024).make()
    dst = File("dst", size = 1024 * 1024 * 2).make()
    run2ok([mscp, "-H", "-vvv", "-C", compress, src_prefix + src.path, dst_prefix + "dst"])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()


testhost = "mscptestlocalhost"
testhost_prefix = "{}:{}/".format(testhost, os.getcwd()) # use current dir
param_testhost_prefix = [
    ("", testhost_prefix), (testhost_prefix, "")
]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_testhost_prefix)
def test_config_ok(mscp, src_prefix, dst_prefix):
    config = "/tmp/mscp_test_ssh_config"
    with open(config, "w") as f:
        f.write("host {}\n".format(testhost))
        f.write("    hostname localhost\n")

    src = File("src", size = 1024 * 1024).make()
    dst = File("dst", size = 1024 * 1024 * 2).make()
    run2ok([mscp, "-H", "-vvv", "-F", config,
            src_prefix + src.path, dst_prefix + "dst"])

    os.remove(config)
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_testhost_prefix)
def test_config_ng(mscp, src_prefix, dst_prefix):
    config = "/tmp/mscp_test_ssh_config"
    with open(config, "w") as f:
        f.write("\n") # use empty ssh_config

    src = File("src", size = 1024 * 1024).make()
    dst = File("dst", size = 1024 * 1024 * 2).make()
    run2ng([mscp, "-H", "-vvv", "-F", config,
            src_prefix + src.path, dst_prefix + "dst"])

    os.remove(config)
    src.cleanup()
    dst.cleanup()
