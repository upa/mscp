
Build docker containers.

```console
cd ..

docker build -t mscp-ubuntu:20.04 -f docker/ubuntu-20.04.Dockerfile .

docker build -t mscp-ubuntu:22.04 -f docker/ubuntu-22.04.Dockerfile .

docker build -t mscp-rocky:8.8 -f docker/rocky-8.Dockerfile .
```

Test `mscp` in the containers.

```console
docker run --init --rm mscp-ubuntu:20.04 /mscp/scripts/test-in-container.sh

docker run --init --rm mscp-ubuntu:22.04 /mscp/scripts/test-in-container.sh

docker run --init --rm mscp-rocky:8.9 /mscp/scripts/test-in-container.sh
```

Retrieve deb/rpm packages.

```console
docker run --rm -v (pwd):/out mscp-ubuntu:20.04 \
       cp /mscp/build/mscp_ubuntu-20.04-x86_64.deb /out/

docker run --rm -v (pwd):/out mscp-ubuntu:22.04 \
       cp /mscp/build/mscp_ubuntu-22.04-x86_64.deb /out/

docker run --rm -v (pwd):/out mscp-rocky:8.8 \
       cp /mscp/build/mscp_rocky-8.8-x86_64.rpm /out/
```

I don't know whether these are good way.