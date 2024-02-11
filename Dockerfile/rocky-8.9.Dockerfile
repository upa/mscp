FROM rockylinux:8.9

ARG REQUIREDPKGS

# install pytest, sshd for test, and rpm-build
RUN set -ex && yum -y install \
	${REQUIREDPKGS}	\
	python3 python3-pip python3-devel \
	openssh openssh-server openssh-clients rpm-build

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

RUN rm -rf /run/nologin


ARG mscpdir="/mscp"

COPY . ${mscpdir}

# build
RUN cd ${mscpdir}			\
        && rm -rf build			\
        && cmake -B build		\
        && cd ${mscpdir}/build          \
	&& make	-j 2			\
	&& make install
