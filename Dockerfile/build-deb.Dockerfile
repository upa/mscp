FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
RUN set -ex && apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates build-essential devscripts debhelper gcc make cmake

ARG mscpdir="/debbuild/mscp"

COPY . ${mscpdir}

# install build dependency
RUN ${mscpdir}/scripts/install-build-deps.sh

# build
RUN cd ${mscpdir} 	\
	&& debuild -us -uc -S \
	&& mv ${mscpdir} /

# Then all debuild output files exsit at /debbuild

