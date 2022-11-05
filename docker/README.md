
Build `mscp` in docker containers.

```console
cd ..

docker build -t mscp-ubuntu:20.04 -f docker/Dockerfile-ubuntu-20.04 .
docker run -it --rm -v (pwd):/out mscp-ubuntu:20.04 \
       cp /mscp/build/mscp_0.0.0-ubuntu-20.04-x86_64.deb /out/

docker build -t mscp-ubuntu:22.04 -f docker/Dockerfile-ubuntu-22.04 .
docker run -it --rm -v (pwd):/out mscp-ubuntu:22.04 \
       cp /mscp/build/mscp_0.0.0-ubuntu-22.04-x86_64.deb /out/

docker build -t mscp-centos:8 -f docker/Dockerfile-centos-8 .
docker run -it --rm -v (pwd):/out mscp-centos:8 \
       cp /mscp/build/mscp_0.0.0-centos-8-x86_64.rpm /out/
```


Test `mscp` in a ubuntu:latest docker container.

```console
cd ..

docker build --rm -t mscp-test -f docker/Dockerfile-test .

docker run --init -it --rm mscp-test bash -c "/usr/sbin/sshd; cd /mscp/build; ctest --verbose"
```

I don't know whether these these are good way.