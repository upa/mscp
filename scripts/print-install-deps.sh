#!/bin/bash -e
#
# Print install dpenedencies on Linux. CMake runs this script to obtain deps for CPACK.
# mscp dependes on packages on which libssh depends.

source /etc/os-release

release=$1

case $release in
	ubuntu-20.04*)
		echo "libc6 (>= 2.27), libgssapi-krb5-2 (>= 1.17), libssl1.1 (>= 1.1.1), zlib1g (>= 1:1.1.4)"
		;;
	ubuntu-22.04*)
		echo "libc6 (>= 2.33), libgssapi-krb5-2 (>= 1.17), libssl3 (>= 3.0.0~~alpha1), zlib1g (>= 1:1.1.4)"
		;;
	centos* | rhel* | rocky* | almalinux*)
		echo "glibc crypto-policies krb5-libs openssl-libs libcom_err"
		;;
	*)
		echo "$(basename $0): unsupported install dependency: $release"
		exit 1
esac
