#!/bin/bash -e
#
# Install build dpenedencies.

source /etc/os-release
set -x

case $ID in
	ubuntu*)
		apt-get install -y gcc make cmake libssh-dev
		;;
	centos* | rhel* | rocky*)
		yum install -y gcc make cmake libssh-devel rpm-build
		;;
	*)
		echo "unsupported dependency install: $ID"
		exit 1
esac
