
## Build mscp as src.rpm for publishing at COPR

### How to build

```shell-session
cd mscp
mkdir build && cd build

cmake ..  make build-srpm
```

`make build-srpm` builds mscp src.rpm inside a docker container.

After that, there is `mscp-0.1.3-1.el9.src.rpm` under the `build`
directory. The next step for publishing is to upload the src.rpm to
[coprs/upaaa/mscp](https://copr.fedorainfracloud.org/coprs/upaaa/mscp/build/6983569/).
