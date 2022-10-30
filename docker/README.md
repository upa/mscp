
Build `mscp` in docker containers.

```console
docker build -t mscp-ubuntu:20.04 -f Dockerfile-ubuntu-20.04 .
docker run -it --rm -v (pwd):/out mscp-ubuntu:20.04 \
       cp /mscp/build/mscp_0.0.0-ubuntu-20.04-x86_64.deb /out/

docker build -t mscp-ubuntu:22.04 -f Dockerfile-ubuntu-22.04 .
docker run -it --rm -v (pwd):/out mscp-ubuntu:22.04 \
       cp /mscp/build/mscp_0.0.0-ubuntu-22.04-x86_64.deb /out/

docker build -t mscp-centos:8 -f Dockerfile-centos-8 .
docker run -it --rm -v (pwd):/out mscp-centos:8 \
       cp /mscp/build/mscp_0.0.0-centos-8-x86_64.rpm /out/
```

I don't know whether this is a good way.