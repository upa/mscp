FROM rockylinux:9

ARG REQUIREDPKGS
ARG MSCP_VERSION

# install pytest, sshd for test, and rpm-build
RUN set -ex && yum -y install ${REQUIREDPKGS} rpm-build rpmdevtools

ARG mscpdir="/mscp-${MSCP_VERSION}"
ARG mscptgz="mscp-${MSCP_VERSION}.tar.gz"

COPY . ${mscpdir}

# prepare rpmbuild
RUN rpmdev-setuptree \
	&& rm -rf ${mscpdir}/build	\
	&& tar zcvf /${mscptgz} --exclude-vcs ${mscpdir}	\
	&& cp /${mscptgz} ~/rpmbuild/SOURCES/	\
	&& cp ${mscpdir}/rpm/mscp.spec ~/rpmbuild/SPECS/

# build rpm and src.rpm
RUN rpmbuild -ba ~/rpmbuild/SPECS/mscp.spec
