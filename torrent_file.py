import hashlib
import random
from collections import OrderedDict
import bencodepy
from loguru import logger
from utils.errors import ErrOpenTorrentFile


class TorrentMetadata:
    def __init__(self, path: str) -> None:
        try:
            logger.debug(f"reading file from {path}")
            self._raw_torrent = bencodepy.decode_from_file(path)
        except Exception as e:
            logger.error(f"failed to read file, err ={e}")
            raise ErrOpenTorrentFile(e)

        self.encoding = self.get_encoding(self._raw_torrent)
        logger.debug(f"set {self.encoding} encoding")

        self._raw_metadata = self.extract_torrent_metadata(self._raw_torrent)

        self.tracker_list = self.get_announce(self._raw_metadata)
        self.file_name = self._raw_metadata['info']['name']
        self.piece_length = self._raw_metadata['info']['piece length']
        self.pieces = self._raw_metadata['info']['pieces']
        self.info_hash = self._generate_info_hash()
        self.file_size = self._get_file_size()
        self.peer_id = ('-PC0001-' + ''.join([str(random.randint(0, 9)) for i in range(12)])).encode()
        self.client_port = 6881
        self.block_length = 16 * (2 ** 10)
        self.pieces_count = int(len(self.pieces) / 20)
        self.num_pieces_uploaded = 0
        self.num_pieces_downloaded = 0
        self.num_pieces_left = 0

    def _generate_info_hash(self):
        sha1_hash = hashlib.sha1()
        # get the raw info value
        raw_info = self._raw_torrent[b'info']
        # update the sha1 hash value
        sha1_hash.update(bencodepy.encode(raw_info))
        return sha1_hash.digest()

    def _get_file_size(self):
        if 'files' in self._raw_metadata['info'].keys():
            files_dictionary = self._raw_metadata['info']['files']
            files = [(file_data['length'], file_data['path']) for file_data in files_dictionary]
            file_size = 0
            for file_length, file_path in files:
                file_size += file_length
        else:
            file_size = self._raw_metadata['info']['length']
        return file_size

    def extract_torrent_metadata(self, raw_torrent):
        torrent_extract = OrderedDict()

        for key, value in raw_torrent.items():
            new_key = key.decode(self.encoding)

            if type(value) is OrderedDict:
                torrent_extract[new_key] = self.extract_torrent_metadata(value)

            elif type(value) is list and new_key == 'files':
                torrent_extract[new_key] = list(map(lambda x: self.extract_torrent_metadata(x), value))

            elif type(value) is list and new_key == 'path':
                torrent_extract[new_key] = value[0].decode(self.encoding)

            elif type(value) is list and new_key == 'url-list' or new_key == 'collections':
                torrent_extract[new_key] = list(map(lambda x: x.decode(self.encoding), value))

            elif type(value) is list:
                try:
                    torrent_extract[new_key] = list(map(lambda x: x[0].decode(self.encoding), value))
                finally:
                    torrent_extract[new_key] = value

            elif type(value) is bytes and new_key != 'pieces':
                try:
                    torrent_extract[new_key] = value.decode(self.encoding)
                finally:
                    torrent_extract[new_key] = value
            else:
                torrent_extract[new_key] = value

        return torrent_extract

    @staticmethod
    def get_encoding(raw_torrent):
        if b'encoding' in raw_torrent.keys():
            encoding = raw_torrent[b'encoding'].decode()
        else:
            encoding = "UTF-8"
        return encoding

    @staticmethod
    def get_announce(raw_metadata):
        if 'announce-list' in raw_metadata.keys():
            trackers_url_list = [i[0] for i in raw_metadata['announce-list']]
        else:
            trackers_url_list = raw_metadata['announce']
        return trackers_url_list