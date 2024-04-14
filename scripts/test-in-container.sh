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

## Alpine default sshd disables TcpForwarding, which is required for proxyjump test
sed -i -e 's/AllowTcpForwarding no/AllowTcpForwarding yes/' /etc/ssh/sshd_config

# Run sshd
if [ ! -e /var/run/sshd.pid ]; then
	/usr/sbin/sshd
	sleep 1
fi

for port in 22 8022; do
	ssh-keyscan -p $port localhost >> ${HOME}/.ssh/known_hosts
	ssh-keyscan -p $port ip6-localhost >> ${HOME}/.ssh/known_hosts
	ssh-keyscan -p $port 127.0.0.1 >> ${HOME}/.ssh/known_hosts
	ssh-keyscan -p $port ::1 >> ${HOME}/.ssh/known_hosts
done

# Run test
python3 -m pytest -v ../test 
