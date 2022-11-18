
Patch(es) in this directory introduces `sftp_async_write()` and
`sftp_async_write_end()` to libssh. Those implementations are derived
from https://github.com/limes-datentechnik-gmbh/libssh. See [Re: SFTP
Write async](https://archive.libssh.org/libssh/2020-06/0000004.html).

```console
git clone https://git.libssh.org/projects/libssh.git/ --depth=1 -b libssh-0.10.4
cd libssh
git apply ../pathc/libssh-0.10.4.patch

# then build libssh
```
