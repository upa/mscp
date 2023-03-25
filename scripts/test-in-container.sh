#!/bin/bash -e
#
# Run this script in mscp docker containers.
# This script runs end-to-end test with installed mscp.

script_dir=$(cd $(dirname ${0}) && pwd)
cd $script_dir

set -x

# Run sshd
if [ ! -e /var/run/sshd.pid ]; then
	/usr/sbin/sshd
	sleep 1
fi

ssh-keyscan localhost >> ${HOME}/.ssh/known_hosts

# Run test
python3 -m pytest ../test -v
