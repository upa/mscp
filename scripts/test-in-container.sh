#!/bin/bash -e
#
# Run this script in docker containers. This script installs mscp from built package
# and run test for mscp in the installed path.

source /etc/os-release
script_dir=$(cd $(dirname ${0}) && pwd)
cd $script_dir
project_version=$(cat ../VERSION)
arch=$(uname -p)

set -x

# install package
case $ID in
        ubuntu*)
		pkg=mscp_${project_version}-${ID}-${VERSION_ID}-${arch}.deb
		dpkg -i ../build/$pkg
                ;;
        centos* | rhel* | rocky*)
		pkg=mscp_${project_version}-${ID}-${VERSION_ID}-${arch}.rpm
		rpm -iv ../build/$pkg
                ;;
        *)
                echo "unsupported test platform: $ID"
                exit 1
esac

# Run sshd
if [ ! -e /var/run/sshd.pid ]; then
	/usr/sbin/sshd
fi

# Run test
python3 -m pytest ../test -v
