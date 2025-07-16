

## Build mscp as deb package

`make build-deb` produces a mscp deb package and related files. This
target builds mscp with `debuild` inside a docker container
(Dockerfile is `docker/build-deb.Docerfile`).


```console
mkdir build && cd build && cmake ..
make build-deb
```

After that:

```console
$ ls debbuild
mscp_0.1.4.dsc		 mscp_0.1.4_source.buildinfo  mscp_0.1.4.tar.xz
mscp_0.1.4_source.build  mscp_0.1.4_source.changes
```

### To publush mscp in launchpad PPA:

1. write changes in `debian/changelog` at main branch (the date
   command needed here is `date -R`)
2. switch to `ppa-focal` or `ppa-jammy` branch
3. rebase to the `main` branch and modify `debian/changes`:
   * change `mscp (X.X.X) UNRELEASED;` to `mscp (X.X.X-1~RELEASENAME) RELEASENAME;`
	 where `RELEASENAME` is `focal` or `jammy`.
4. run `make build-deb` at the build directory and `cd debbuild`
5. sign the files with `debsign -k [GPGKEYID] mscp_X.X.X~X_source.changes`
5. upload the files with `dput ppa:upaa/mscp mscp_X.X.X~X_source.changes`


## Build mscp as (source) rpm package

`make build-srpm` produces a mscp src.rpm package. This target builts
mscp with `rpmbuild` inside a docker container (Dockerfile is
`docker/build-srpm.Dockerfile`, generated from
`build-srpm.Dockerfile.in` by cmake).

```console
mkdir build && cd build && cmake ..
make build-srpm
```

After that:

```console
$ ls *.rpm
mscp-0.1.3-1.el9.src.rpm
```

### To publish mscp in COPR:

1. update `rpm/mscp.spec.in`, the `changelog` section (the date
   command needed here is `date "+%a %b %d %Y"`)
2. run `make build-srpm`
3. download `mscp-X.X.X-1.yyy.src.rpm`
4. upload the src.rpm to Build page at COPR.



## Update Document

The docuemnt is `doc/mscp.rst` (at present). When `mscp.1.in` is
modified, run `make update-rst` to make it up to date.

```console
mkdir build cd build && cmake ..
make update-rst
```

