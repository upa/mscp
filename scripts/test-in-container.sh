#!/bin/bash -e
#
# Run this script in mscp docker containers.
# This script runs end-to-end test with installed mscp.

script_dir=$(cd $(dirname ${0}) && pwd)
cd $script_dir

set -x

# sshd Linsten on 22 and 8022
echo "Port 22" >> /etc/ssh/sshd_config
echo "Port 8022" >> /etc/ssh/sshd_config

# Run sshd
if [ ! -e /var/run/sshd.pid ]; then
	/usr/sbin/sshd
	sleep 1
fi

ssh-keyscan localhost >> ${HOME}/.ssh/known_hosts
ssh-keyscan 127.0.0.1 >> ${HOME}/.ssh/known_hosts
ssh-keyscan ::1 >> ${HOME}/.ssh/known_hosts

# Run test
python3 -m pytest -v ../test 
