
"""
test_e2e.py: End-to-End test for mscp executable.
"""

import platform
import pytest
import getpass
import datetime
import time
import os
import shutil

from subprocess import check_call, CalledProcessError
from util import File, check_same_md5sum


def run2ok(args, env = None, quiet = False):
    cmd = list(map(str, args))
    if not quiet:
        print("cmd: {}".format(" ".join(cmd)))
    check_call(cmd, env = env)

def run2ng(args, env = None, timeout = None, quiet = False):
    if timeout:
        args = ["timeout", "-s", "INT", timeout] + args
    cmd = list(map(str, args))
    if not quiet:
        print("cmd: {}".format(" ".join(cmd)))
    with pytest.raises(CalledProcessError):
        check_call(cmd, env = env)



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
    run2ok([mscp, "-vvv", src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_failed_to_copy_nonexistent_file(mscp, src_prefix, dst_prefix):
    src = "nonexistent_src"
    dst = "nonexistent_dst"
    run2ng([mscp, "-vvv", src_prefix + src, dst_prefix + dst])

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
    run2ok([mscp, "-vvv", src_prefix + s1.path, src_prefix + s2.path, dst_prefix + "dst"])
    assert check_same_md5sum(s1, d1)
    assert check_same_md5sum(s2, d2)
    s1.cleanup()
    s2.cleanup()
    d1.cleanup()
    d2.cleanup()


remote_v6_prefix = "[::1]:{}/".format(os.getcwd())
param_remote_v6_prefix = [
    ("", remote_v6_prefix), (remote_v6_prefix, "")
]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_v6_prefix)
@pytest.mark.parametrize("s1, s2, d1, d2", param_double_copy)
def test_double_copy_with_ipv6_notation(mscp, src_prefix, dst_prefix, s1, s2, d1, d2):
    s1.make()
    s2.make()
    run2ok([mscp, "-vvv",
            src_prefix + s1.path, src_prefix + s2.path, dst_prefix + "dst"])
    assert check_same_md5sum(s1, d1)
    assert check_same_md5sum(s2, d2)
    s1.cleanup()
    s2.cleanup()
    d1.cleanup()
    d2.cleanup()


remote_user_v6_prefix = "{}@[::1]:{}/".format(getpass.getuser(), os.getcwd())
param_remote_user_v6_prefix = [
    ("", remote_user_v6_prefix), (remote_user_v6_prefix, "")
]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_user_v6_prefix)
@pytest.mark.parametrize("s1, s2, d1, d2", param_double_copy)
def test_double_copy_with_user_and_ipv6_notation(mscp, src_prefix, dst_prefix,
                                                 s1, s2, d1, d2):
    s1.make()
    s2.make()
    run2ok([mscp, "-vvv",
            src_prefix + s1.path, src_prefix + s2.path, dst_prefix + "dst"])
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

    run2ok([mscp, "-vvv", src_prefix + src_dir, dst_prefix + dst_dir])
    for sf, df in zip(src, dst):
        assert check_same_md5sum(sf, df)

    run2ok([mscp, "-vvv", src_prefix + src_dir, dst_prefix + dst_dir])
    for sf, df in zip(src, twice):
        assert check_same_md5sum(sf, df)

    for sf, df, tf in zip(src, dst, twice):
        sf.cleanup()
        df.cleanup()
        tf.cleanup()


param_dir_copy_single = [
    ("src_dir", "dst_dir",
     File("src_dir/t1", size = 1024 * 1024),
     File("dst_dir/src_dir/t1"),
     )
]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("src_dir, dst_dir, src, dst", param_dir_copy_single)
def test_dir_copy_single(mscp, src_prefix, dst_prefix, src_dir, dst_dir, src, dst):
    src.make()
    os.mkdir(dst_dir)
    run2ok([mscp, "-vvv", src_prefix + src_dir, dst_prefix + dst_dir])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_override_single_file(mscp, src_prefix, dst_prefix):
    src = File("src", size = 128).make()
    dst = File("dst", size = 128).make()
    assert not check_same_md5sum(src, dst)

    run2ok([mscp, "-vvv", src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)

    src.cleanup()
    dst.cleanup()

absolute_remote_prefix = "localhost:"
param_absolute_remote_prefix = [
    ("", absolute_remote_prefix), (absolute_remote_prefix, "")
]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_absolute_remote_prefix)
def test_copy_file_under_root_to_dir(mscp, src_prefix, dst_prefix):
    src = File("/mscp-test-src", size = 1024).make()
    dst = File("/tmp/mscp-test-src")

    run2ok([mscp, "-vvv", src_prefix + src.path,
            dst_prefix + os.path.dirname(dst.path)])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup(preserve_dir = True)


@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_min_chunk(mscp, src_prefix, dst_prefix):
    src = File("src", size = 16 * 1024).make()
    dst = File("dst")

    run2ok([mscp, "-vvv", "-s", 32768, src_prefix + src.path, dst_prefix + dst.path])
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

    run2ok([mscp, "-vvv", src_prefix + src_glob_path, dst_prefix + dst_path])
    for src, dst in zip(srcs, dsts):
        assert check_same_md5sum(src, dst)
        src.cleanup()
        dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_thread_affinity(mscp, src_prefix, dst_prefix):
    src = File("src", size = 64 * 1024).make()
    dst = File("dst")

    run2ok([mscp, "-vvv", "-n", 4, "-m", "0x01",
            src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)

    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_cannot_override_file_with_dir(mscp, src_prefix, dst_prefix):
    src = File("src", size = 128).make()
    dst = File("dst").make()

    run2ng([mscp, "-vvv", src_prefix + src.path, dst_prefix + "dst/src"])

    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_transfer_zero_bytes(mscp, src_prefix, dst_prefix):
    src = File("src", size = 0).make()
    dst = File("dst")
    run2ok([mscp, "-vvv", src_prefix + src.path, dst_prefix + "dst"])
    assert os.path.exists("dst")
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_override_dst_having_larger_size(mscp, src_prefix, dst_prefix):
    src = File("src", size = 1024 * 1024).make()
    dst = File("dst", size = 1024 * 1024 * 2).make()
    run2ok([mscp, "-vvv", src_prefix + src.path, dst_prefix + "dst"])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_dont_truncate_dst(mscp, src_prefix, dst_prefix):
    f = File("srcanddst", size = 1024 * 1024 * 128).make()
    md5_before = f.md5sum()
    run2ok([mscp, "-vvv", src_prefix + f.path, dst_prefix + f.path])
    md5_after = f.md5sum()
    assert md5_before == md5_after
    f.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_copy_readonly_file(mscp, src_prefix, dst_prefix):
    """When a source file permission is r--r--r--, if chmod(r--r--r--)
    runs first on the remote side, following truncate() and setutime()
    fail due to permission deneid. So, run chmod() after truncate()
    and setutime()

    """
    src = File("src", size = 1024 * 1024 * 128, perm = 0o444).make()
    dst = File("dst")
    run2ok([mscp, "-vvv", src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_dont_make_conns_more_than_chunks(mscp, src_prefix, dst_prefix):
    # copy 100 files with -n 20 -I 1 options. if mscp creates 20 SSH
    # connections although all files have been copied, it is error.
    srcs = []
    dsts = []
    for n in range(100):
        srcs.append(File("src/src-{:06d}".format(n), size=1024).make())
        dsts.append(File("dst/src-{:06d}".format(n)))
    start = time.time()
    run2ok([mscp, "-v", "-n", "20", "-I", "1",
            src_prefix + "src", dst_prefix + "dst"])
    end = time.time()
    for s, d in zip(srcs, dsts):
        assert check_same_md5sum(s, d)
    shutil.rmtree("src")
    shutil.rmtree("dst")
    assert((end - start) < 10)


@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_bwlimit(mscp, src_prefix, dst_prefix):
    """Copy 100MB file with 100Mbps bitrate, this requires 8 seconds."""
    src = File("src", size = 100 * 1024 * 1024).make()
    dst = File("dst")

    start = datetime.datetime.now().timestamp()
    run2ok([mscp, "-vvv", "-L", "100m", src_prefix + "src", dst_prefix + "dst"])
    end = datetime.datetime.now().timestamp()
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()
    assert end - start > 7


@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("src, dst", param_single_copy)
def test_set_port_ng(mscp, src_prefix, dst_prefix, src, dst):
    src.make()
    run2ng([mscp, "-vvv", "-P", 21, src_prefix + src.path, dst_prefix + dst.path])
    src.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("src, dst", param_single_copy)
def test_set_port_ok(mscp, src_prefix, dst_prefix, src, dst):
    src.make()
    run2ok([mscp, "-vvv", "-P", 8022, src_prefix + src.path, dst_prefix + dst.path])
    src.cleanup()

def test_v4only(mscp):
    src = File("src", size = 1024).make()
    dst = File("dst")
    dst_prefix = "localhost:{}/".format(os.getcwd())
    run2ok([mscp, "-vvv", "-4", src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

def test_v6only(mscp):
    src = File("src", size = 1024).make()
    dst = File("dst")
    dst_prefix = "ip6-localhost:{}/".format(os.getcwd())
    run2ok([mscp, "-vvv", "-6", src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

def test_v4_to_v6_should_fail(mscp):
    src = File("src", size = 1024).make()
    dst = File("dst")
    dst_prefix = "[::1]:{}/".format(os.getcwd())
    run2ng([mscp, "-vvv", "-4", src.path, dst_prefix + dst.path])
    src.cleanup()

def test_v6_to_v4_should_fail(mscp):
    src = File("src", size = 1024).make()
    dst = File("dst")
    dst_prefix = "127.0.0.1:{}/".format(os.getcwd())
    run2ng([mscp, "-vvv", "-6", src.path, dst_prefix + dst.path])
    src.cleanup()

def test_quiet_mode(capsys, mscp):
    src = File("src", size = 1024).make()
    dst = File("dst")
    dst_prefix = "127.0.0.1:{}/".format(os.getcwd())
    run2ok([mscp, "-vvv", "-q", src.path, dst_prefix + dst.path], quiet=True)
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()
    captured = capsys.readouterr()
    assert not captured.out
    assert not captured.err

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_set_conn_interval(mscp, src_prefix, dst_prefix):
    srcs = []
    dsts = []
    for x in range(500):
        srcs.append(File("src/file{}".format(x), size = 128).make())
        dsts.append(File("dst/file{}".format(x)))
    run2ok([mscp, "-vvv", "-I", 1, src_prefix + "src", dst_prefix + "dst"])

    for src, dst in zip(srcs, dsts):
        assert check_same_md5sum(src, dst)
        src.cleanup()
        dst.cleanup()

compressions = ["yes", "no", "none"]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("compress", compressions)
def test_compression(mscp, src_prefix, dst_prefix, compress):
    src = File("src", size = 1024 * 1024).make()
    dst = File("dst", size = 1024 * 1024 * 2).make()
    run2ok([mscp, "-vvv", "-C", compress, src_prefix + src.path, dst_prefix + "dst"])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_ccalgo(mscp, src_prefix, dst_prefix):
    src = File("src", size = 1024 * 1024).make()
    dst = File("dst").make()
    if platform.system() == "Darwin":
        # Darwin does not support TCP_CONGESTION
        algo = "cubic"
        run = run2ng
    elif platform.system() == "Linux":
        # Linux supports TCP_CONGESTION
        with open("/proc/sys/net/ipv4/tcp_allowed_congestion_control", "r") as f:
            algo = f.read().strip().split().pop()
        run = run2ok
    run([mscp, "-vvv", "-g", algo, src_prefix + src.path, dst_prefix + "dst"])


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
    run2ok([mscp, "-vvv", "-F", config,
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
    run2ng([mscp, "-vvv", "-F", config,
            src_prefix + src.path, dst_prefix + "dst"])

    os.remove(config)
    src.cleanup()
    dst.cleanup()


param_valid_option_ok = [
    [ "-o", "Port=8022" ],
    [ "-o", "Port=8022", "-o", "User=root" ],
    [ "-o", "unknown-option-is-silently-ignored" ],
]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("option", param_valid_option_ok)
def test_inline_option_ok(mscp, src_prefix, dst_prefix, option):
    """ change port number with -o option. it should be ok. """
    src = File("src", size = 1024 * 1024).make()
    dst = File("dst")
    run2ok([mscp, "-vvv"] + option +
           [src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()


param_valid_option_ng = [
    [ "-o", "Port=8023" ],
    [ "-o", "User=invaliduser" ],
]
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
@pytest.mark.parametrize("option", param_valid_option_ng)
def test_inline_option_ng(mscp, src_prefix, dst_prefix, option):
    """ change port number with -o option. it should be ng. """
    src = File("src", size = 1024 * 1024).make()
    dst = File("dst")
    run2ng([mscp, "-vvv"] + option +
           [src_prefix + src.path, dst_prefix + dst.path])
    src.cleanup()


@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_porxyjump_ok(mscp, src_prefix, dst_prefix):
    """ test -J proxyjump option"""
    src = File("src", size = 10 * 1024 * 1024).make()
    dst = File("dst")
    # use small min-chunk-size to use multiple connections
    run2ok([mscp, "-n", 4, "-s", 1024 * 1024, "-vvv",
            "-J", "localhost:8022",
            src_prefix + src.path, dst_prefix + dst.path])
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()


@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_porxyjump_ng(mscp, src_prefix, dst_prefix):
    """ test -J proxyjump option, invalid jump node causes fail"""
    src = File("src", size = 10 * 1024 * 1024).make()
    dst = File("dst")
    # use small min-chunk-size to use multiple connections
    run2ng([mscp, "-n", 4, "-s", 1024 * 1024, "-vvv",
            "-J", "invaliduser@localhost:8022",
            src_prefix + src.path, dst_prefix + dst.path])
    src.cleanup()

# username test assumes that this test runs inside a container, see Dockerfiles
def test_specify_passphrase_via_env(mscp):
    src = File(os.getcwd() + "/src", size = 1024).make()
    dst = File("/home/test/dst")
    env = os.environ
    env["MSCP_SSH_AUTH_PASSPHRASE"]  = "keypassphrase"
    run2ok([mscp, "-vvv", "-l", "test", "-i", "/home/test/.ssh/id_rsa_test",
            src.path, "localhost:" + dst.path], env = env)
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

def test_specify_invalid_passphrase_via_env(mscp):
    src = File(os.getcwd() + "/src", size = 1024).make()
    dst = File("/home/test/dst")
    env = os.environ
    env["MSCP_SSH_AUTH_PASSPHRASE"]  = "invalid-keypassphrase"
    run2ng([mscp, "-vvv", "-l", "test", "-i", "/home/test/.ssh/id_rsa_test",
            src.path, "localhost:" + dst.path], env = env)
    src.cleanup()

def test_specify_password_via_env(mscp):
    src = File(os.getcwd() + "/src", size = 1024).make()
    dst = File("/home/test/dst")
    env = os.environ
    env["MSCP_SSH_AUTH_PASSWORD"]  = "userpassword"
    run2ok([mscp, "-vvv", "-l", "test",
            src.path, "localhost:" + dst.path], env = env)
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

def test_specify_invalid_password_via_env(mscp):
    src = File(os.getcwd() + "/src", size = 1024).make()
    dst = File("/home/test/dst")
    env = os.environ
    env["MSCP_SSH_AUTH_PASSWORD"]  = "invalid-userpassword"
    run2ng([mscp, "-vvv", "-l", "test",
            src.path, "localhost:" + dst.path], env = env)
    src.cleanup()

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_10k_files(mscp, src_prefix, dst_prefix):
    srcs = []
    dsts = []
    for n in range(10000):
        srcs.append(File("src/src-{:06d}".format(n), size=1024).make())
        dsts.append(File("dst/src-{:06d}".format(n)))
    run2ok([mscp, "-v", src_prefix + "src", dst_prefix + "dst"])
    for s, d in zip(srcs, dsts):
        assert check_same_md5sum(s, d)
    shutil.rmtree("src")
    shutil.rmtree("dst")

@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_checkpoint_dump_and_resume(mscp, src_prefix, dst_prefix):
    src1 = File("src1", size = 64 * 1024 * 1024).make()
    src2 = File("src2", size = 64 * 1024 * 1024).make()
    dst1 = File("dst/src1")
    dst2 = File("dst/src2")
    run2ok([mscp, "-vvv", "-W", "checkpoint", "-D",
            src_prefix + "src1", src_prefix + "src2", dst_prefix + "dst"])
    assert os.path.exists("checkpoint")

    run2ok([mscp, "-vvv", "-R", "checkpoint"])
    assert check_same_md5sum(src1, dst1)
    assert check_same_md5sum(src2, dst2)
    src1.cleanup()
    src2.cleanup()
    dst1.cleanup()
    dst2.cleanup()
    os.remove("checkpoint")

@pytest.mark.parametrize("timeout", [ 1, 2, 3, 4, 5 ])
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_checkpoint_interrupt_large_file(mscp, timeout, src_prefix, dst_prefix):
    """Copy two 100MB files with 200Mbps -> 4 sec + 4 sec """
    src1 = File("src1", size = 100 * 1024 * 1024).make()
    src2 = File("src2", size = 100 * 1024 * 1024).make()
    dst1 = File("dst/src1")
    dst2 = File("dst/src2")
    run2ng([mscp, "-vv", "-W", "checkpoint", "-L", "200m",
            src_prefix + "src1", src_prefix + "src2", dst_prefix + "dst"],
           timeout = timeout)
    assert os.path.exists("checkpoint")

    run2ok([mscp, "-vv", "-R", "checkpoint"])
    assert check_same_md5sum(src1, dst1)
    assert check_same_md5sum(src2, dst2)
    src1.cleanup()
    src2.cleanup()
    dst1.cleanup()
    dst2.cleanup()
    os.remove("checkpoint")

@pytest.mark.parametrize("timeout", [ 1, 2, 3, 4, 5 ])
@pytest.mark.parametrize("src_prefix, dst_prefix", param_remote_prefix)
def test_checkpoint_interrupt_many_files(mscp, timeout, src_prefix, dst_prefix):
    """Copy 100 1-MB files with 4 connections, and interrupt and
    resume the transfer
    """

    files = []
    for x in range(100):
        files.append((
            File("src/{:03d}".format(x), size = 1024 * 1024).make(),
            File("dst/{:03d}".format(x))
        ))

    run2ng([mscp, "-vv", "-W", "checkpoint", "-L", "80m", "-n", 4,
            src_prefix + "src",  dst_prefix + "dst"],
           timeout = timeout)
    assert os.path.exists("checkpoint")

    run2ok([mscp, "-vv", "-R", "checkpoint"])

    for src, dst in files:
        assert check_same_md5sum(src, dst)
        src.cleanup()
        dst.cleanup()

    os.remove("checkpoint")

