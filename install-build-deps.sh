#!/bin/bash -e

source /etc/os-release
set -x

case $ID in
	ubuntu*)
		apt-get install -y gcc make cmake libssh-dev
		;;
	centos* | rhel*)
		dnf install -y gcc make cmake libssh-devel rpm-build
		;;
	*)
		echo "unsupported dependency install: $ID"
		exit 1
esac
