FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ARG mscpdir="/mscp"

COPY . ${mscpdir}

RUN set -ex && apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates

# install numpy and pytest, and sshd for test
RUN apt-get install -y --no-install-recommends  \
        python3 python3-pip openssh-server

RUN python3 -m pip install numpy pytest


# preparation for sshd
RUN  mkdir /var/run/sshd        \
        && ssh-keygen -f /root/.ssh/id_rsa -N ""                \
        && mv /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys


# install build dependency
RUN ${mscpdir}/scripts/install-build-deps.sh


# build
RUN cd ${mscpdir}			\
	&& rm -rf build			\
	&& cmake -B build -DBUILD_PKG=1	\
	&& cd ${mscpdir}/build		\
	&& make				\
	&& cpack -G DEB CPackConfig.cmake 
