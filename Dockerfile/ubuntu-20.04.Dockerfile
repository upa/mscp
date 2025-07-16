FROM ubuntu:20.04

ARG REQUIREDPKGS

ARG DEBIAN_FRONTEND=noninteractive
RUN set -ex && apt-get update && apt-get install -y --no-install-recommends \
	${REQUIREDPKGS} ca-certificates python3 python3-pip python3-dev openssh-server

RUN python3 -m pip install pytest

# preparation for sshd
RUN mkdir /var/run/sshd        \
	&& ssh-keygen -A	\
        && ssh-keygen -f /root/.ssh/id_rsa -N ""                \
        && cat /root/.ssh/id_rsa.pub > /root/.ssh/authorized_keys

# create test user
RUN useradd -m -d /home/test test       \
        && echo "test:userpassword" | chpasswd \
        && mkdir -p /home/test/.ssh     \
        && ssh-keygen -f /home/test/.ssh/id_rsa_test -N "keypassphrase" \
        && cat /home/test/.ssh/id_rsa_test.pub >> /home/test/.ssh/authorized_keys \
        && chown -R test:test /home/test \
        && chown -R test:test /home/test/.ssh


ARG mscpdir="/mscp"

COPY . ${mscpdir}

# build
RUN cd ${mscpdir}			\
	&& rm -rf build			\
	&& cmake -B build		\
	&& cd ${mscpdir}/build		\
	&& make	-j 2			\
	&& make install

