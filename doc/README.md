
# Document

The base file of documents is `mscp.1.in`. The manpage of mscp and
`doc/mscp.rst` are generated from `mscp.1.in`.

When `mscp.1.in` is changed, update `doc/mscp.rst` by:

1. `cd build`
2. `cmake ..`
3. `make update-mscp-rst`