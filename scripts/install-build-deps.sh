#!/bin/bash -eu
#
# Install build dpenedencies.

platform=$(uname -s)

if [ -e /etc/os-release ]; then
	source /etc/os-release
	platform=${platform}-${ID}
fi

set -x

case $platform in
	Darwin)
		brew install openssl@1.1
		;;
	Linux-ubuntu*)
		apt-get install -y \
			gcc make cmake zlib1g-dev libssl-dev libkrb5-dev
		;;
	Linux-centos* | Linux-rhel* | Linux-rocky* | Linux-almalinux)
		yum install -y \
			gcc make cmake zlib-devel openssl-devel rpm-build
		;;
	*)
		echo "unsupported platform: $platform"
		exit 1
		;;
esac
