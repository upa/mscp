FROM rockylinux:8.6

ARG mscpdir="/mscp"

COPY . ${mscpdir}

# install numpy and pytest, sshd for test, and rpm-build
RUN set -ex && yum -y update && yum -y install \
	python3 python3-pip openssh openssh-server openssh-clients rpm-build

RUN python3 -m pip install numpy pytest


# preparation for sshd
RUN  mkdir /var/run/sshd        \
	&& ssh-keygen -A	\
        && ssh-keygen -f /root/.ssh/id_rsa -N ""                \
        && mv /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys

# install build dependency
RUN ${mscpdir}/scripts/install-build-deps.sh

# build
RUN cd ${mscpdir}			\
        && rm -rf build			\
        && cmake -B build -DBUILD_PKG=1 \
        && cd ${mscpdir}/build          \
	&& make				\
	&& cpack -G RPM CPackConfig.cmake

