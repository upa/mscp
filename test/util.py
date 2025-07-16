
import hashlib
import os


def check_same_md5sum(fa, fb):
    return (fa.md5sum() == fb.md5sum())


class File():
    def __init__(self, path, size = 0, content = "random", perm = 0o664):
        if not content in ["zero", "random"]:
            raise ValueError("invalid type: {}".format(content))
        self.path = path
        self.size = size
        self.content = content
        self.perm = perm

    def __repr__(self):
        return "<file:{} {}-bytes>".format(self.path, self.size)

    def __str__(self):
        return self.path

    def make(self, size = None):
        if size:
            self.size = size

        d = os.path.dirname(self.path)
        if d:
            os.makedirs(d, exist_ok = True)
        if self.content == "zero":
            self.make_content_zero()
        elif self.content == "random":
            self.make_content_random()
        else:
            raise ValueError("invalud content type: {}".format(self.content))
        os.chmod(self.path, self.perm)
        return self

    def make_content_zero(self):
        with open(self.path, "wb") as f:
            f.seek(self.size, 0)

    def make_content_random(self):
        with open(self.path, "wb") as f:
            f.write(os.urandom(self.size))

    def cleanup(self, preserve_dir = False):
        os.remove(self.path)
        if preserve_dir:
            return
        tmp = os.path.dirname(self.path)
        while tmp and not tmp in [".", "/"]:
            if len(os.listdir(tmp)) == 0:
                os.rmdir(tmp)
            tmp = os.path.dirname(tmp)

    def md5sum(self):
        m = hashlib.md5()
        with open(self.path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096 * m.block_size), b''):
                m.update(chunk)
        return m.hexdigest()

