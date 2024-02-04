
Dockerfiles for building and testing mscp.

Build container:

```
docker build -t mscp-DIST:VER -f docker/DIST-VER.Dockerfile .
```

Run test:

```
docker run --init --rm mscp-DST:VER /mscp/scripts/test-in-container.sh
```

`cmake` provides custom targets to build and test mscp in the
containers. See `make docker-*` targets. `make docker-build-all`
builds all container images and `make docker-test-all` runs the test
in all container images.