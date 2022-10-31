
This test assumes that the user executing the test can ssh to the
localhost without password.

- Run pytest through ctest.

```console
cd build
cmake ..
make test # or make test ARGS='-V'
```
