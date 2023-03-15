
"""
test_python.py: Testing libmscp through the mscp python binding.
"""

import pytest
import mscp
import os
from util import File, check_same_md5sum

def test_create_and_release():
    m = mscp.mscp("localhost", mscp.LOCAL2REMOTE)
    m.cleanup()


""" copy test """

remote = "localhost"
remote_prefix = "{}/".format(os.getcwd()) # use current dir
param_remote_prefix_and_direction = [
    ("", remote_prefix, mscp.LOCAL2REMOTE), (remote_prefix, "", mscp.REMOTE2LOCAL)
]


param_single_copy = [
    (File("src", size = 64), File("dst")),
    (File("src", size = 4096 * 1), File("dst")),
    (File("src", size = 128 * 1024 * 1024), File("dst")),
]

@pytest.mark.parametrize("src_prefix, dst_prefix, direction",
                         param_remote_prefix_and_direction)
@pytest.mark.parametrize("src, dst", param_single_copy)
def test_single_copy(src_prefix, dst_prefix, direction, src, dst):
    src.make()
    m = mscp.mscp(remote, direction)
    m.copy(src_prefix + src.path, dst_prefix + dst.path)
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()


param_double_copy = [
    (File("src1", size = 1024 * 1024), File("src2", size = 1024 * 1024),
     File("dst/src1"), File("dst/src2")
     )
]
@pytest.mark.parametrize("src_prefix, dst_prefix, direction",
                         param_remote_prefix_and_direction)
@pytest.mark.parametrize("s1, s2, d1, d2", param_double_copy)
def test_double_copy(src_prefix, dst_prefix, direction, s1, s2, d1, d2):
    s1.make()
    s2.make()
    mscp.mscp(remote, direction).copy([src_prefix + s1.path, src_prefix + s2.path],
                                      dst_prefix + "dst")
    assert check_same_md5sum(s1, d1)
    assert check_same_md5sum(s2, d2)
    s1.cleanup()
    s2.cleanup()
    d1.cleanup()
    d2.cleanup()

    
param_single_copy = [
    (File("src", size = 1024 * 1024 * 4), File("dst")),
]

param_kwargs = [
    { "nr_threads": 6 },
    { "nr_ahead": 64 },
    { "min_chunk_sz": 1 * 1024 * 1024 },
    { "max_chunk_sz": 64 * 1024 * 1024 },
    { "coremask": "0x0f" },
    { "max_startups": 5 },
    { "severity": mscp.SEVERITY_NONE },
    { "cipher": "aes128-gcm@openssh.com" },
    { "compress": "yes" },
    { "no_hostkey_check": True },
    { "enable_nagle": True },
]

@pytest.mark.parametrize("src_prefix, dst_prefix, direction",
                         param_remote_prefix_and_direction)
@pytest.mark.parametrize("src, dst", param_single_copy)
@pytest.mark.parametrize("kw", param_kwargs)
def test_kwargs(src_prefix, dst_prefix, direction, src, dst, kw):
    src.make()
    m = mscp.mscp(remote, direction, **kw)
    m.copy(src_prefix + src.path, dst_prefix + dst.path)
    assert check_same_md5sum(src, dst)
    src.cleanup()
    dst.cleanup()

def test_login_failed():
    m = mscp.mscp("asdfasdf@" + remote, mscp.LOCAL2REMOTE)
    with pytest.raises(RuntimeError) as e:
        m.connect()

    m = mscp.mscp(remote, mscp.LOCAL2REMOTE, login_name = "asdfadsf")
    with pytest.raises(RuntimeError) as e:
        m.connect()

    m = mscp.mscp(remote, mscp.LOCAL2REMOTE, port = "65534")
    with pytest.raises(RuntimeError) as e:
        m.connect()
