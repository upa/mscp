FROM rockylinux:8.9

# install pytest, sshd for test, and rpm-build
RUN set -ex && yum -y install \
	python3 python3-pip python3-devel openssh openssh-server openssh-clients rpm-build

RUN python3 -m pip install pytest


# preparation for sshd
RUN  mkdir /var/run/sshd        \
	&& ssh-keygen -A	\
        && ssh-keygen -f /root/.ssh/id_rsa -N ""                \
        && mv /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys

ARG mscpdir="/mscp"

COPY . ${mscpdir}

# install build dependency
RUN ${mscpdir}/scripts/install-build-deps.sh

# build
RUN cd ${mscpdir}			\
        && rm -rf build			\
        && cmake -B build		\
        && cd ${mscpdir}/build          \
	&& make	-j 2			\
	&& make install
