
_retry_import_pymscp = False

try:
    import pymscp
except ImportError:
    _retry_import_pymscp = True

if _retry_import_pymscp:
    """ libmscp.so is not installed on system library paths. So retry
    to import libmscp.so installed on the mscp python module
    directory.
    """
    import os
    import sys
    import ctypes

    if sys.platform == "linux":
        libmscp = "libmscp.so"
    elif sys.platform == "darwin":
        libmscp = "libmscp.dylib"

    mscp_dir = os.path.dirname(__file__)
    ctypes.cdll.LoadLibrary("{}/{}".format(mscp_dir, libmscp))
    import pymscp


# inherit static values from pymscp
LOCAL2REMOTE    = pymscp.LOCAL2REMOTE
REMOTE2LOCAL    = pymscp.REMOTE2LOCAL
SEVERITY_NONE   = pymscp.SEVERITY_NONE
SEVERITY_ERR    = pymscp.SEVERITY_ERR
SEVERITY_WARN   = pymscp.SEVERITY_WARN
SEVERITY_NOTICE = pymscp.SEVERITY_NOTICE
SEVERITY_INFO   = pymscp.SEVERITY_INFO
SEVERITY_DEBUG  = pymscp.SEVERITY_DEBUG

__STATE_INIT      = 0
__STATE_CONNECTED = 1
__STATE_PREPARED  = 2
__STATE_RUNNING   = 3
__STATE_STOPPED   = 4
__STATE_JOINED    = 5
__STATE_CLEANED   = 6
__STATE_RELEASED  = 7

_state_str = {
    __STATE_INIT:      "init",
    __STATE_CONNECTED: "connected",
    __STATE_PREPARED:  "prepared",
    __STATE_RUNNING:   "running",
    __STATE_STOPPED:   "stopped",
    __STATE_JOINED:    "joined",
    __STATE_CLEANED:   "cleaned",
    __STATE_RELEASED:  "released",
}


class mscp:


    def __init__(self, remote: str, direction: int, **kwargs):
        self.remote = remote
        self.direction = direction
        kwargs["remote"] = remote
        kwargs["direction"] = direction
        self.m = pymscp.mscp_init(**kwargs)

        self.src_paths = []
        self.dst_path = None
        self.state = __STATE_INIT

    def __str__(self):
        return "mscp:{}:{}".format(self.remote, self.__state2str())

    def __repr__(self):
        return "<{}>".format(str(self))

    def __del__(self):

        if not hasattr(self, "state"):
            return # this instance failed on mscp_init

        if self.state == __STATE_RUNNING:
            self.stop()
        if self.state == __STATE_STOPPED:
            self.join()

        self.cleanup()
        self.release()

    def __state2str(self):
        return _state_str[self.state]


    def connect(self):
        if not (self.state == __STATE_INIT or state.state == __STATE_CLEANED):
            raise RuntimeError("invalid mscp state: {}".format(self.__state2str()))
        pymscp.mscp_connect(m = self.m)
        self.state = __STATE_CONNECTED

    def add_src_path(self, src_path: str):
        self.src_paths.append(src_path)
        pymscp.mscp_add_src_path(m = self.m, src_path = src_path)

    def set_dst_path(self, dst_path: str):
        self.dst_path = dst_path
        pymscp.mscp_set_dst_path(m = self.m, dst_path = dst_path);

    def prepare(self):
        if self.state != __STATE_CONNECTED:
            raise RuntimeError("invalid mscp state: {}".format(self.__state2str()))
        if not self.src_paths:
            raise RuntimeError("src path list is empty")
        if not self.dst_path:
            raise RuntimeError("dst path is not set")

        pymscp.mscp_prepare(m = self.m)
        self.state = __STATE_PREPARED

    def start(self):
        if self.state != __STATE_PREPARED:
            raise RuntimeError("invalid mscp state: {}".format(self.__state2str()))

        pymscp.mscp_start(m = self.m)
        self.state = __STATE_RUNNING

    def stop(self):
        if self.state != __STATE_RUNNING:
            raise RuntimeError("invalid mscp state: {}".format(self.__state2str()))
        pymscp.mscp_stop(m = self.m)
        self.state = __STATE_STOPPED

    def join(self):
        if not (self.state == __STATE_RUNNING or self.state == __STATE_STOPPED):
            raise RuntimeError("invalid mscp state: {}".format(self.__state2str()))
        pymscp.mscp_join(m = self.m)
        self.state = __STATE_JOINED

    def stats(self):
        return pymscp.mscp_get_stats(m = self.m)

    def cleanup(self):
        if self.state == __STATE_RUNNING:
            raise RuntimeError("invalid mscp state: {}".format(self.__state2str()))
        pymscp.mscp_cleanup(m = self.m)
        self.state = __STATE_CLEANED

    def release(self):
        if self.state != __STATE_CLEANED:
            raise RuntimeError("invalid mscp state: {}".format(self.__state2str()))
        pymscp.mscp_free(m = self.m)
        self.state = __STATE_RELEASED

    # Simple interface: mscp.copy(src, dst)
    def copy(self, src, dst, nonblock = False):
        if self.state < __STATE_CONNECTED:
            self.connect()

        if type(src) == list:
            for path in src:
                self.add_src_path(path)
        elif type(src) == str:
            self.add_src_path(src)
        else:
            raise ValueError("src must be str of list: '{}'".format(src))

        self.set_dst_path(dst)
        
        self.prepare()
        self.start()
        if nonblock:
            return

        self.join()
        self.cleanup()
