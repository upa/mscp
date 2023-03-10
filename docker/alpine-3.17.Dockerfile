FROM alpine:3.17

# Build mscp with conan to create single binary mscp

ARG mscpdir="/mscp"

COPY . ${mscpdir}

RUN apk add --no-cache \
	gcc make cmake python3 py3-pip perl linux-headers libc-dev	\
	openssh bash python3-dev g++

RUN pip3 install conan pytest

# Build mscp as a single binary
RUN conan profile detect --force
RUN cd ${mscpdir}							\
	&& rm -rf build							\
	&& conan install . --output-folder=build --build=missing	\
	&& cd ${mscpdir}/build						\
	&& cmake ..							\
		-DCMAKE_BUILD_TYPE=Release				\
		-DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake		\
		-DBUILD_STATIC=ON -DBUILD_CONAN=ON			\
	&& make								\
	&& cp mscp /usr/bin/						\
	&& cp mscp /mscp/build/mscp_0.0.6-alpine-3.17-x86_64.static

# copy mscp to PKG FILE NAME because this build doesn't use CPACK

# preparation for sshd
RUN ssh-keygen -A
RUN  mkdir /var/run/sshd        \
        && ssh-keygen -f /root/.ssh/id_rsa -N ""                \
        && mv /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys
