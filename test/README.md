
This test assumes that the user executing the test can ssh to the
localhost without password.

- Run pytest through ctest.

```console
python3 -m pip install pytest numpy

cd build
cmake ..
ctest --verbose # or `make test ARGS='-V'`
```
