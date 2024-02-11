
Dockerfiles for building and testing mscp.

cmake provides custom targets to build and test mscp in the containers
See `make docker-*` targets. `make docker-build-all` builds all
container images, and `make docker-test-all` runs the test in all
container images.