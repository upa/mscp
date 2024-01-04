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


https://github.com/upa/mscp/assets/184632/19230f57-be7f-4ef0-98dd-cb4c460f570d

--------------------------------------------------------------------

Differences from `scp` on usage:

- Remote-to-remote copy is not supported.
- `-r` option is not needed to transfer directories.
- and any other differences I have not implemented and noticed.

Paper:
- Ryo Nakamura and Yohei Kuga. 2023. Multi-threaded scp: Easy and Fast File Transfer over SSH. In Practice and Experience in Advanced Research Computing (PEARC '23). Association for Computing Machinery, New York, NY, USA, 320–323. https://doi.org/10.1145/3569951.3597582

## Install

- macOS

```console
brew install upa/tap/mscp
```

- Ubuntu
```console
sudo add-apt-repository ppa:upaa/mscp
sudo apt-get install mscp
```

- Rocky 8.8
```console
yum install https://github.com/upa/mscp/releases/latest/download/mscp_rocky-8.8-x86_64.rpm
```

- Alma 8.8
```console
yum install https://github.com/upa/mscp/releases/latest/download/mscp_almalinux-8.8-x86_64.rpm
```

- Linux with single binary `mscp` (x86_64 only, and not optimal performance)
```console
wget https://github.com/upa/mscp/releases/latest/download/mscp.linux.x86.static -O /usr/local/bin/mscp
chmod 755 /usr/local/bin/mscp
```


## Build

mscp depends on a patched [libssh](https://www.libssh.org/).  The
patch introduces asynchronous SFTP Write, which is derived from
https://github.com/limes-datentechnik-gmbh/libssh (see [Re: SFTP Write
async](https://archive.libssh.org/libssh/2020-06/0000004.html)).

Currently macOS and Linux (Ubuntu, Rocky and Alma) are supported.

```console
# clone this repository
git clone https://github.com/upa/mscp.git
cd mscp

# prepare patched libssh
git submodule update --init
patch -d libssh -p1 < patch/libssh-0.10.6.patch

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
mscp v0.0.8: copy files over multiple ssh connections

Usage: mscp [vqDHdNh] [-n nr_conns] [-m coremask] [-u max_startups]
            [-s min_chunk_sz] [-S max_chunk_sz] [-a nr_ahead] [-b buf_sz]
            [-l login_name] [-p port] [-i identity_file]
            [-c cipher_spec] [-M hmac_spec] [-C compress] source ... target
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
[=======================================] 100%   49B /49B   198.8B/s   00:00 ETA
```

```console
$ mscp -vv test 10.0.0.1:
file: test/test1 -> ./test/test1
file: test/testdir/asdf -> ./test/testdir/asdf
file: test/testdir/qwer -> ./test/testdir/qwer
file: test/test2 -> ./test/test2
we have only 4 chunk(s). set number of connections to 4
connecting to localhost for a copy thread...
connecting to localhost for a copy thread...
connecting to localhost for a copy thread...
copy start: test/test1
copy start: test/test2
copy start: test/testdir/asdf
copy start: test/testdir/qwer
copy done: test/test1
copy done: test/test2
copy done: test/testdir/qwer
copy done: test/testdir/asdf
[=======================================] 100%   49B /49B   198.1B/s   00:00 ETA
```

- Full usage

```console
$ mscp -h
mscp v0.0.9-11-g5802679: copy files over multiple ssh connections

Usage: mscp [vqDHdNh] [-n nr_conns] [-m coremask] [-u max_startups]
            [-s min_chunk_sz] [-S max_chunk_sz] [-a nr_ahead] [-b buf_sz]
            [-l login_name] [-p port] [-F ssh_config] [-i identity_file]
            [-c cipher_spec] [-M hmac_spec] [-C compress] source ... target

    -n NR_CONNECTIONS  number of connections (default: floor(log(cores)*2)+1)
    -m COREMASK        hex value to specify cores where threads pinned
    -u MAX_STARTUPS    number of concurrent outgoing connections (default: 8)
    -s MIN_CHUNK_SIZE  min chunk size (default: 64MB)
    -S MAX_CHUNK_SIZE  max chunk size (default: filesize/nr_conn)

    -a NR_AHEAD        number of inflight SFTP commands (default: 32)
    -b BUF_SZ          buffer size for i/o and transfer

    -v                 increment verbose output level
    -q                 disable output
    -D                 dry run. check copy destinations with -vvv
    -r                 no effect

    -l LOGIN_NAME      login name
    -p PORT            port number
    -F CONFIG          path to user ssh config (default ~/.ssh/config)
    -i IDENTITY        identity file for public key authentication
    -c CIPHER          cipher spec
    -M HMAC            hmac spec
    -C COMPRESS        enable compression: yes, no, zlib, zlib@openssh.com
    -H                 disable hostkey check
    -d                 increment ssh debug output level
    -N                 enable Nagle's algorithm (default disabled)
    -h                 print this help
```


Note: mscp is still under development, and the author is not
responsible for any accidents due to mscp.
