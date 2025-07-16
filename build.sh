#!/bin/bash
set -e

# 自动还原libssh子模块到干净状态
cd libssh
if [ -d .git ]; then
    echo "Resetting libssh submodule to clean state..."
    git checkout .
    git clean -fdx
else
    echo "libssh is not a git submodule, skipping reset."
fi
cd ..

# 检查补丁是否已应用（以sftp_async_write为特征）
if ! grep -q sftp_async_write libssh/include/libssh/sftp.h; then
    PATCH_FILE="patch/$(git --git-dir=./libssh/.git describe).patch"
    if [ -f "$PATCH_FILE" ]; then
        echo "Patching libssh..."
        patch -d libssh -p1 < "$PATCH_FILE"
    else
        echo "Patch file $PATCH_FILE not found!"
        exit 1
    fi
else
    echo "libssh patch already applied, skipping."
fi

# 安装依赖
bash ./scripts/install-build-deps.sh

# 创建build目录并进入
mkdir -p build
cd build

# 配置cmake（macOS自动加OPENSSL_ROOT_DIR）
if [[ "$OSTYPE" == "darwin"* ]]; then
    cmake .. -DOPENSSL_ROOT_DIR=$(brew --prefix)/opt/openssl@3 "$@"
else
    cmake .. "$@"
fi

# 编译
make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)

echo "Build finished. You can run 'sudo make install' in build/ if需要安装." 