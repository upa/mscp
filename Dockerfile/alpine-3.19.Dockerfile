FROM alpine:3.19

# Build mscp with conan to create single binary mscp

RUN apk add --no-cache \
	gcc make cmake python3 py3-pip perl linux-headers libc-dev	\
	openssh bash python3-dev py3-pytest g++

RUN pip3 install --break-system-packages conan

# preparation for sshd
RUN ssh-keygen -A
RUN  mkdir /var/run/sshd        \
        && ssh-keygen -f /root/.ssh/id_rsa -N ""                \
        && mv /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys


# Build mscp as a single binary
RUN conan profile detect --force

ARG mscpdir="/mscp"

COPY . ${mscpdir}

RUN cd ${mscpdir}							\
	&& rm -rf build							\
	&& conan install . --output-folder=build --build=missing	\
	&& cd ${mscpdir}/build						\
	&& cmake ..							\
		-DCMAKE_BUILD_TYPE=Release				\
		-DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake		\
		-DBUILD_CONAN=ON -DBUILD_STATIC=ON			\
	&& make	-j 2							\
	&& make install

