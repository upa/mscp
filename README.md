# mscp

`mscp`, a variant of `scp`, copies files over multiple ssh (sftp)
sessions. Multiple threads in mscp transfer (1) multiple files
simultaneously and (2) a large file in parallel. It may shorten the
waiting time for transferring a lot of/large files over networks.

You can use `mscp` like `scp`, e.g., `mscp example.com:srcfile
/tmp/dstfile`. Remote hosts only need to run `sshd` supporting the
SFTP subsystem, and you need to be able to ssh to the hosts (as
usual).

Differences from `scp` are:

- remote glob on remote shell expansion is not supported.
- remote to remote copy is not supported.
- `-r` option is not needed.
- and any other differences I have not noticed and implemented...

## Build

mscp depends on [libssh](https://www.libssh.org/).

- macOS

```console
brew install libssh
```

- ubuntu

```console
sudo apt-get install libssh-dev
```

- rhel

```console
sudo yum install libssh-devel
```

Clone and build this repositoy.

```console
git clone https://github.com/upa/mscp.git
cd mscp

mkdir build && cd build
cmake .. && make

# install the mscp binary to CMAKE_INSTALL_PREFIX/bin (usually /usr/local/bin)
make install
```

## Run

- Usage

```shell-session
$ mscp -h
mscp: copy files over multiple ssh connections

Usage: mscp [CvqDdh] [-n nr_conns] [-s min_chunk_sz] [-S max_chunk_sz]
            [-b sftp_buf_sz] [-B io_buf_sz]
            [-l login_name] [-p port] [-i identity_file]
            [-c cipher_spec] source ... target

    -n NR_CONNECTIONS  number of connections (default: half of # of cpu cores)
    -s MIN_CHUNK_SIZE  min chunk size (default: 64MB)
    -S MAX_CHUNK_SIZE  max chunk size (default: filesize / nr_conn)
    -b SFTP_BUF_SIZE   buf size for sftp_read/write (default 131072B)
    -B IO_BUF_SIZE     buf size for read/write (default 131072B)
                       Note that this value is derived from
                       qemu/block/ssh.c. need investigation...
    -v                 increment verbose output level
    -q                 disable output
    -D                 dry run

    -l LOGIN_NAME      login name
    -p PORT            port number
    -i IDENTITY        identity file for publickey authentication
    -c CIPHER          cipher spec, see `ssh -Q cipher`
    -C                 enable compression on libssh
    -d                 increment ssh debug output level
    -h                 print this help
```

- Example: copy an 8GB file on tmpfs over a 100Gbps link
  - Two Intel Xeon Gold 6130 machines directly connected with Intel E810 100Gbps NICs.

```shell-session
$ mscp /tmp/test.img 10.0.0.1:/tmp/
[===============================================================] 100% 8GB/8GB 3.02GB/s 
$
```

- `-v` options increment verbose output level.

```shell-session
$ mscp test 10.0.0.1:
[===============================================================] 100% 13B/13B 2.41KB/s 

$ mscp -v test 10.0.0.1:
file test/test.txt (local) -> ./test/test.txt (remote) 9B
file test/test2/2.txt (local) -> ./test/test2/2.txt (remote) 2B
file test/1.txt (local) -> ./test/1.txt (remote) 2B
copy start: test/test.txt
copy start: test/1.txt
copy start: test/test2/2.txt
copy done: test/1.txt
copy done: test/test2/2.txt
copy done: test/test.txt
[===============================================================] 100% 13B/13B 2.51KB/s 

$ mscp -vv -n 4 test 10.0.0.1:
connecting to 10.0.0.1 for checking destinations...
file test/test.txt (local) -> ./test/test.txt (remote) 9B
file test/test2/2.txt (local) -> ./test/test2/2.txt (remote) 2B
file test/1.txt (local) -> ./test/1.txt (remote) 2B
connecting to 10.0.0.1 for a copy thread...
connecting to 10.0.0.1 for a copy thread...
connecting to 10.0.0.1 for a copy thread...
connecting to 10.0.0.1 for a copy thread...
copy start: test/test.txt
copy start: test/1.txt
copy start: test/test2/2.txt
copy done: test/test.txt
copy done: test/test2/2.txt
copy done: test/1.txt
[===============================================================] 100% 13B/13B 3.27KB/s
```

Note: mscp is still under development, and the author is not
responsible for any accidents on mscp.
