FROM ubuntu:22.04

ARG REQUIREDPKGS

ARG DEBIAN_FRONTEND=noninteractive
RUN set -ex && apt-get update && apt-get install -y --no-install-recommends \
	${REQUIREDPKGS} ca-certificates \
	build-essential devscripts debhelper gcc make cmake

ARG mscpdir="/debbuild/mscp"

COPY . ${mscpdir}

# build
RUN cd ${mscpdir} 	\
	&& debuild -us -uc -S \
	&& mv ${mscpdir} /

# Then all debuild output files exsit at /debbuild

