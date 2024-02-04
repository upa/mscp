FROM rockylinux:9

# install pytest, sshd for test, and rpm-build
RUN set -ex && yum -y install rpm-build rpmdevtools

ARG mscpdir="/mscp-0.1.3"
ARG mscptgz="mscp-0.1.3.tar.gz"

COPY . ${mscpdir}

# install build dependency
RUN ${mscpdir}/scripts/install-build-deps.sh

# prepare rpmbuild
RUN rpmdev-setuptree \
	&& rm -rf ${mscpdir}/build	\
	&& tar zcvf /${mscptgz} --exclude-vcs ${mscpdir}	\
	&& cp /${mscptgz} ~/rpmbuild/SOURCES/	\
	&& cp ${mscpdir}/rpm/mscp.spec ~/rpmbuild/SPECS/

# build rpm and src.rpm
RUN rpmbuild -ba ~/rpmbuild/SPECS/mscp.spec
