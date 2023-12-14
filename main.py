from torrent_file import TorrentMetadata
from tracker import UDPTracker, HTTPTracker, Tracker

torrent_metadata = TorrentMetadata("")

print(torrent_metadata.tracker_list)

tracker = Tracker(torrent_metadata)

