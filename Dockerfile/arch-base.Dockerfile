FROM archlinux:base

ARG REQUIREDPKGS

# install pyest and openssh for test
RUN set -ex && pacman -Syy && pacman --noconfirm -S ${REQUIREDPKGS} openssh python-pytest

RUN mkdir /var/run/sshd        \
        && ssh-keygen -A        \
        && ssh-keygen -f /root/.ssh/id_rsa -N ""                \
        && cat /root/.ssh/id_rsa.pub > /root/.ssh/authorized_keys

# disable PerSourcePenaltie, which would distrub test:
# https://undeadly.org/cgi?action=article;sid=20240607042157
RUN echo "PerSourcePenalties=no" > /etc/ssh/sshd_config.d/90-mscp-test.conf

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
RUN cd ${mscpdir}                       \
        && rm -rf build                 \
        && cmake -B build               \
        && cd ${mscpdir}/build          \
        && make -j 2                    \
        && make install
