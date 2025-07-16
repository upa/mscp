> **注意：本项目已将可执行文件名由 mscp 更名为 mpscp，以便区分多网卡/多路径增强版。mpscp 支持多网卡并发、精准流量分流，适合高性能多路径传输场景。**

# mpscp: multi-threaded scp

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

推荐使用一键构建脚本：

```sh
./build.sh
```

该脚本会自动：
- 初始化子模块
- 检查并自动打补丁到libssh（如已打过则跳过）
- 安装依赖
- 配置并编译

编译完成后，可进入build目录执行：

```sh
sudo make install
```

---

### 传统手动构建流程（如需自定义）

```sh
# clone this repository
git clone https://github.com/upa/mscp.git
cd mscp

git submodule update --init
patch -d libssh -p1 < patch/$(git --git-dir=./libssh/.git describe).patch
bash ./scripts/install-build-deps.sh
mkdir build && cd build
cmake ..
make
sudo make install
```

> **注意**：如从[Releases页面](https://github.com/upa/mscp/releases)下载的`mscp-X.X.X.tar.gz`源码包，无需打补丁。

## Documentation

[manpage](/doc/mscp.rst) is available.
