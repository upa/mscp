# mscp: multi-threaded scp

[![build on ubuntu](https://github.com/upa/mscp/actions/workflows/build-ubuntu.yml/badge.svg)](https://github.com/upa/mscp/actions/workflows/build-ubuntu.yml) [![build on macOS](https://github.com/upa/mscp/actions/workflows/build-macos.yml/badge.svg)](https://github.com/upa/mscp/actions/workflows/build-macos.yml) [![test](https://github.com/upa/mscp/actions/workflows/test.yml/badge.svg)](https://github.com/upa/mscp/actions/workflows/test.yml)


`mscp`, a variant of `scp`, copies files over multiple ssh (SFTP)
connections. Multiple threads and connections in mscp transfer (1)
multiple files simultaneously and (2) a large file in parallel. It
would shorten the waiting time for transferring a lot of/large files
over networks.

You can use `mscp` like `scp`, for example, `mscp
user@example.com:srcfile /tmp/dstfile`. Remote hosts only need to run
standard `sshd` supporting the SFTP subsystem (e.g. openssh-server),
and you need to be able to ssh to the hosts as usual. `mscp` does not
require anything else.

https://user-images.githubusercontent.com/184632/206889149-7cc6178a-6f0f-41e6-855c-d25e15a9abc5.mp4


Differences from `scp` on usage:

- remote glob on remote shell expansion is not supported.
- remote to remote copy is not supported.
- `-r` option is not needed.
- and any other differences I have not implemented and noticed.


## Install

- homebrew

```console
brew install upa/tap/mscp
```

- Linux

Download a package for your environment from [Releases
page](https://github.com/upa/mscp/releases).


## Build

mscp depends on a patched [libssh](https://www.libssh.org/).  The
patch introduces asynchronous SFTP Write, which is derived from
https://github.com/limes-datentechnik-gmbh/libssh (see [Re: SFTP Write
async](https://archive.libssh.org/libssh/2020-06/0000004.html)).

Currently macOS and Linux (Ubuntu, CentOS, Rocky) are supported.

```console
# clone this repository
git clone https://github.com/upa/mscp.git
cd mscp

# prepare patched libssh
git submodule update --init
patch -d libssh -p1 < patch/libssh-0.10.4.patch

# install build dependency
bash ./scripts/install-build-deps.sh

# configure mscp
mkdir build && cd build
cmake ..

# in macOS, you may need OPENSSL_ROOT_DIR for cmake:
# cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix)/opt/openssl@1.1

# build
make

# install the mscp binary to CMAKE_INSTALL_PREFIX/bin (usually /usr/local/bin)
make install
```
Source tar balls (`mscp-X.X.X.tar.gz`, not `Source code`) in
[Releases page](https://github.com/upa/mscp/releases) contains the patched version
of libssh. So you can start from cmake with it.

## Run

- Usage

```console
$ mscp
mscp v0.0.5: copy files over multiple ssh connections

Usage: mscp [vqDCHdNh] [-n nr_conns] [-m coremask]
            [-s min_chunk_sz] [-S max_chunk_sz] [-a nr_ahead] [-b buf_sz]
            [-l login_name] [-p port] [-i identity_file]
            [-c cipher_spec] [-M hmac_spec] source ... target
```

- Example: copy a 15GB file on memory over a 100Gbps link
  - Two Intel Xeon Gold 6130 machines directly connected with Intel E810 100Gbps NICs.
  - Default `openssh-server` runs on the remote host.

```console
$ mscp /var/ram/test.img 10.0.0.1:/var/ram/
[======================================] 100%   15GB/15GB    1.7GB/s  00:00 ETA
```

```console
# with some optimizations. top speed reaches 3.0GB/s.
$ mscp -n 5 -m 0x1f -c aes128-gcm@openssh.com /var/ram/test.img 10.0.0.1:/var/ram/
[======================================] 100%   15GB/15GB    2.4GB/s  00:00 ETA
```

- `-v` option increments verbose output level.

```console
$ mscp test 10.0.0.1:
[======================================] 100%   26B /26B     6.3KB/s  00:00 ETA
```

```console
$ mscp -vv test 10.0.0.1:
number of connections: 7
connecting to 10.0.0.1 for checking destinations...
file test/testdir/asdf (local) -> ./test/testdir/asdf (remote) 9B
file test/testdir/qwer (local) -> ./test/testdir/qwer (remote) 5B
file test/test1 (local) -> ./test/test1 (remote) 6B
file test/test2 (local) -> ./test/test2 (remote) 6B
we have only 4 chunk(s). set number of connections to 4
connecting to 10.0.0.1 for a copy thread...
connecting to 10.0.0.1 for a copy thread...
connecting to 10.0.0.1 for a copy thread...
copy start: test/test1
copy start: test/test2
copy done: test/test1
copy start: test/testdir/asdf
copy done: test/test2
copy start: test/testdir/qwer
copy done: test/testdir/qwer
copy done: test/testdir/asdf
[======================================] 100%   26B /26B     5.2KB/s  00:00 ETA
```

- Full usage

```console
$ mscp -h
mscp v0.0.6: copy files over multiple ssh connections

Usage: mscp [vqDCHdNh] [-n nr_conns] [-m coremask]
            [-s min_chunk_sz] [-S max_chunk_sz] [-a nr_ahead] [-b buf_sz]
            [-l login_name] [-p port] [-i identity_file]
            [-c cipher_spec] [-M hmac_spec] source ... target

    -n NR_CONNECTIONS  number of connections (default: floor(log(cores)*2)+1)
    -m COREMASK        hex value to specify cores where threads pinned
    -s MIN_CHUNK_SIZE  min chunk size (default: 64MB)
    -S MAX_CHUNK_SIZE  max chunk size (default: filesize/nr_conn)

    -a NR_AHEAD        number of inflight SFTP commands (default: 32)
    -b BUF_SZ          buffer size for i/o and transfer

    -v                 increment verbose output level
    -q                 disable output
    -D                 dry run
    -r                 no effect

    -l LOGIN_NAME      login name
    -p PORT            port number
    -i IDENTITY        identity file for public key authentication
    -c CIPHER          cipher spec
    -M HMAC            hmac spec
    -C                 enable compression on libssh
    -H                 disable hostkey check
    -d                 increment ssh debug output level
    -N                 disable tcp nodelay (default on)
    -h                 print this help
```


Note: mscp is still under development, and the author is not
responsible for any accidents due to mscp.
