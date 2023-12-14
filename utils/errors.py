class ErrOpenTorrentFile(Exception):
    pass


class ErrUDPTracker(RuntimeError):
    pass


class ErrHttpTracker(RuntimeError):
    pass
