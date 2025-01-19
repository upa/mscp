# mscp: multi-threaded scp

[![build on ubuntu](https://github.com/upa/mscp/actions/workflows/build-ubuntu.yml/badge.svg)](https://github.com/upa/mscp/actions/workflows/build-ubuntu.yml)
[![build on macOS](https://github.com/upa/mscp/actions/workflows/build-macos.yml/badge.svg)](https://github.com/upa/mscp/actions/workflows/build-macos.yml)
[![build on FreeBSD](https://github.com/upa/mscp/actions/workflows/build-freebsd.yml/badge.svg)](https://github.com/upa/mscp/actions/workflows/build-freebsd.yml)
[![test](https://github.com/upa/mscp/actions/workflows/test.yml/badge.svg)](https://github.com/upa/mscp/actions/workflows/test.yml)



`mscp`, a variant of `scp`, copies files over multiple SSH (SFTP)
connections by multiple threads. It enables transferring (1) multiple
files simultaneously and (2) a large file in parallel, reducing the
transfer time for a lot of/large files over networks.

You can use `mscp` like `scp`, for example:

```shell-session
$ mscp srcfile user@example.com:dstfile
```

Remote hosts only need to run standard `sshd` supporting the SFTP
subsystem (e.g. openssh-server), and you need to be able to ssh to the
hosts as usual. `mscp` does not require anything else.


https://github.com/upa/mscp/assets/184632/19230f57-be7f-4ef0-98dd-cb4c460f570d

--------------------------------------------------------------------

Major differences from `scp` on usage:

- Remote-to-remote copy is not supported.
- `-r` option is not needed to transfer directories.
- Checkpointing for resuming failed transfer is supported.
- and any other differences I have not implemented and noticed.

Paper:
- Ryo Nakamura and Yohei Kuga. 2023. Multi-threaded scp: Easy and Fast File Transfer over SSH. In Practice and Experience in Advanced Research Computing (PEARC '23). Association for Computing Machinery, New York, NY, USA, 320–323. https://doi.org/10.1145/3569951.3597582

## Install

- macOS

```console
# Homebrew
brew install upa/tap/mscp

# MacPorts
sudo port install mscp
```

- Ubuntu
```console
sudo add-apt-repository ppa:upaa/mscp
sudo apt-get install mscp
```

- RHEL-based distributions
```console
sudo dnf copr enable upaaa/mscp
sudo dnf install mscp
```

- Single binary `mscp` for x86_64 (not optimal performance)
```console
wget https://github.com/upa/mscp/releases/latest/download/mscp.linux.x86_64.static -O /usr/local/bin/mscp
chmod 755 /usr/local/bin/mscp
```


## Build

mscp depends on a patched [libssh](https://www.libssh.org/). The
patch introduces asynchronous SFTP Write, which is derived from
https://github.com/limes-datentechnik-gmbh/libssh (see [Re: SFTP Write
async](https://archive.libssh.org/libssh/2020-06/0000004.html)).

We test building mscp on Linux (Ubuntu, Rocky, Alma, and Alpine),
macOS, and FreeBSD.


```console
# clone this repository
git clone https://github.com/upa/mscp.git
cd mscp

# prepare patched libssh
git submodule update --init
patch -d libssh -p1 < patch/$(git --git-dir=./libssh/.git describe).patch

# install build dependency
bash ./scripts/install-build-deps.sh

# configure mscp
mkdir build && cd build
cmake ..

# in macOS, you may need OPENSSL_ROOT_DIR for cmake:
# cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix)/opt/openssl@3

# build
make

# install the mscp binary to CMAKE_INSTALL_PREFIX/bin (usually /usr/local/bin)
make install
```

Source tar balls (`mscp-X.X.X.tar.gz`, not `Source code`) in
[Releases page](https://github.com/upa/mscp/releases) contain the patched version
of libssh. So you can start from cmake with it.


## Documentation

[manpage](/doc/mscp.rst) is available.
