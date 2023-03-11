
import pymscp

_STATE_INIT      = 0
_STATE_CONNECTED = 1
_STATE_PREPARED  = 2
_STATE_RUNNING   = 3
_STATE_STOPPED   = 4
_STATE_JOINED    = 5
_STATE_CLEANED   = 6
_STATE_RELEASED  = 7

_state_str = {
    _STATE_INIT:      "init",
    _STATE_CONNECTED: "connected",
    _STATE_PREPARED:  "prepared",
    _STATE_RUNNING:   "running",
    _STATE_STOPPED:   "stopped",
    _STATE_JOINED:    "joined",
    _STATE_CLEANED:   "cleaned",
    _STATE_RELEASED:  "released",
}


class mscp:
    def __init__(self, remote: str, direction: int, **kwargs):
        """
        See src/pymscp.c:wrap_mscp_init() to determine keyword arguments.
        """
        kwargs["remote"] = remote
        kwargs["direction"] = direction
        self.m = pymscp.mscp_init(**kwargs)

        self.src_paths = []
        self.dst_path = None
        self.state = _STATE_INIT

    def _state2str(self):
        return _state_str[self.state]


    def connect(self):
        if not (self.state == _STATE_INIT or state.state == _STATE_CLEANED):
            raise RuntimeError("invalid mscp state: {}".format(_state2str()))
        pymscp.mscp_connect(m = self.m)
        self.state = _CONNECTED

    def add_src_path(self, src_path: str):
        self.src_paths.append(src_path)
        pymscp.mscp_add_src_path(m = self.m, src_path = src_path)

    def set_dst_path(self, dst_path: str):
        self.dst_path = dst_path
        pymscp.mscp_set_dst_path(m = self.m, dst_path = dst_path);

    def prepare(self):
        if self.state != _STATE_CONNCTED:
            raise RuntimeError("invalid mscp state: {}".format(_state2str()))
        if not self.src_paths:
            raise RuntimeError("src path list is empty")
        if not self.dst_path:
            raise RuntimeError("dst path is not set")

        pymscp.mscp_prepare(m = self.m)
        self.state = _STATE_PREPARED

    def start(self):
        if self.state != STATE_PREPARED:
            raise RuntimeError("invalid mscp state: {}".format(_state2str()))

        pymscp.mscp_start(m = self.m)
        self.state = _STATE_RUNNING

    def stop(self):
        if self.state != _STATE_RUNNING:
            raise RuntimeError("invalid mscp state: {}".format(_state2str()))
        pymscp.mscp_stop(m = self.m)
        self.state = _STATE_STOPPED

    def join(self):
        if not (self.state == STATE_RUNNING or self.state == _STATE_STOPPED):
            raise RuntimeError("invalid mscp state: {}".format(_state2str()))
        pymscp.mscp_join(m = self.m)
        self.state = _STATE_JOINED

    def stats(self):
        return pymscp.mscp_get_stats(m = self.m)

    def cleanup(self):
        if self.state != _STATE_JOIND:
            raise RuntimeError("invalid mscp state: {}".format(_state2str()))
        pymscp.mscp_cleanup()
        self.state = _STATE_CLEAND

    def free(self):
        if self.state != _STATE_CLEANED:
            raise RuntimeError("invalid mscp state: {}".format(_state2str()))
        pymscp.mscp_free()


    # Simple interface: mscp.copy(src, dst)
    def copy(self, src, dst, nonblock = False):
        if self.state < _STATE_CONNECTED:
            self.connect()

        if type(src) == list:
            self.src_paths += src
        elif type(src) == str:
            self.src_paths.append(src)
        else:
            raise ValueError("src must be str of list: '{}'".format(src))

        self.dst_path = dst
        
        self.prepare()
        self.start()
        if nonblock:
            return

        self.cleanup()
