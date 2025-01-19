#!/usr/bin/env bash
#
# Install build dpenedencies.

set -e
#set -u

function print_help() {
	echo "$0 [options]"
	echo "    --dont-install         Print required packages."
	echo "    --platform [PLATFORM]  PLATFORM is Kernel-ID, e.g., Linux-ubuntu."
	echo "                           Automatically detected if not specified."
}

platform=$(uname -s)
doinstall=1

if [ -e /etc/os-release ]; then
	source /etc/os-release
	platform=${platform}-${ID}
fi

while getopts h-: opt; do
        optarg="${!OPTIND}"
        [[ "$opt" = - ]] && opt="-$OPTARG"
	case "-${opt}" in
		--dont-install)
			doinstall=0
			;;
		--platform)
			platform=$optarg
			shift
			;;
		-h)
			print_help
			exit 0
			;;
		*)
			print_help
			exit 1
			;;
	esac
done

case $platform in
	Darwin)
		cmd="brew install"
		pkgs="openssl@3"
		;;
	Linux-ubuntu*)
		cmd="apt-get install --no-install-recommends -y"
		pkgs="gcc make cmake zlib1g-dev libssl-dev libkrb5-dev"
		;;
	Linux-centos* | Linux-rhel* | Linux-rocky* | Linux-almalinux)
		cmd="yum install -y"
		pkgs="gcc make cmake zlib-devel openssl-devel rpm-build"
		;;
	Linux-arch*)
		cmd="pacman --no-confirm -S"
		pkgs="gcc make cmake"
		;;
	FreeBSD-freebsd)
		cmd="pkg install"
		pkgs="cmake"
		;;
	*)
		echo "unsupported platform: $platform"
		exit 1
		;;
esac

if [ $doinstall -gt 0 ]; then
	echo do "$cmd $pkgs"
	$cmd $pkgs
else
	echo $pkgs
fi
