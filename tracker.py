import random
import struct
from abc import abstractmethod, ABC
from socket import socket, AF_INET, SOCK_DGRAM

import bencodepy
import httpx
import requests
from loguru import logger

from utils.errors import ErrUDPTracker, ErrHttpTracker
from torrent_file import TorrentMetadata


class Tracker:
    def __init__(self, metadata: TorrentMetadata):
        self.metadata = metadata

        self.client_tracker = None
        self.trackers_list = []
        self.trackers_connection_status = []
        self.connection_success = 1
        self.connection_failure = 2
        self.connection_not_attempted = 3

        for tracker_url in metadata.tracker_list:
            tracker_url = tracker_url.decode()
            if 'http' in tracker_url[:4]:
                tracker: HTTPTracker = HTTPTracker(metadata, tracker_url)
            elif 'udp' in tracker_url[:4]:
                tracker: UDPTracker = UDPTracker(metadata, tracker_url)
            else:
                continue
            # append the tracker class instance
            self.trackers_list.append(tracker)
            # append the connection status
            self.trackers_connection_status.append(self.connection_not_attempted)

    def request_connection(self):
        # attempts connecting with any of the tracker obtained in the list
        for i, tracker in enumerate(self.trackers_list):
            # check if you can request for torrent information
            try:
                tracker.information_request()
                self.trackers_connection_status[i] = self.connection_success
                self.client_tracker = tracker
                break
            except Exception as e:
                logger.debug(f"error connecting to tracker, err = {e}")
                self.trackers_connection_status[i] = self.connection_failure

        return self.client_tracker

class BaseTraker(ABC):
    def __init__(self, metadata: TorrentMetadata):
        self._compact = 1
        # the request parameters of the torrent
        self._request_parameters = {
            'info_hash': metadata.info_hash,
            'peer_id': metadata.peer_id,
            'port': metadata.client_port,
            'uploaded': metadata.num_pieces_uploaded,
            'downloaded': metadata.num_pieces_downloaded,
            'left': metadata.num_pieces_left,
            'compact': self._compact
        }
        self._interval = None
        self._complete = None
        self._incomplete = None
        self.peers_list = []

    @abstractmethod
    def information_request(self):
        ...

    @abstractmethod
    def _parse_response(self, raw_response):
        ...


class UDPTracker(BaseTraker):
    def __init__(self, metadata: TorrentMetadata, tracker_url: str):
        super().__init__(metadata)

        self._tracker_url, self._tracker_port = self.parse_tracker_url(tracker_url)

        # connection id : initially a magic number
        self._connection_id = 0x41727101980
        # action : initially set to connection request action
        self._action = 0x0
        # transaction id : random id to be set by the client
        self._transaction_id = int(random.randrange(0, 255))

    def information_request(self):
        self._tracker_sock = socket(AF_INET, SOCK_DGRAM)
        self._tracker_sock.settimeout(5)

        connection_payload = self._build_connection_payload()

        try:
            # get the connection id from the connection request
            self._connection_id = self._connection_request(connection_payload)

            # announce payload for UDP tracker
            announce_payload = self._build_announce_payload()
            self._raw_announce_reponse = self.announce_request(announce_payload)

            # extract the peers IP, peer port from the announcement response
            self._parse_response(self._raw_announce_reponse)

            # close the socket once the repose is obtained
            self._tracker_sock.close()

            if not (self.peers_list and len(self.peers_list) != 0):
                raise ErrUDPTracker("there is no available peers")

        except Exception as e:
            # close the socket if the response is not obtained
            self._tracker_sock.close()
            raise ErrUDPTracker(e)

    def _parse_response(self, raw_response: bytes) -> None:
        if len(raw_response) < 20:
            raise ErrUDPTracker('Invalid response length in announcing!')

            # first 4 bytes is action
        response_action = struct.unpack_from("!i", raw_response)[0]
        # next 4 bytes is transaction id
        response_transaction_id = struct.unpack_from("!i", raw_response, 4)[0]
        # compare for the transaction id
        if response_transaction_id != self._transaction_id:
            raise ErrUDPTracker('The transaction id in announce response do not match')

        # check if the response contains any error message
        if response_action != 0x1:
            error_msg = struct.unpack_from("!s", raw_response, 8)
            raise ErrUDPTracker("Error while announcing: %s" % error_msg)

        offset = 8
        # interval : specifies minimum time client show wait for sending next request
        self._interval = struct.unpack_from("!i", raw_response, offset)[0]

        offset = offset + 4
        # leechers : the peers not uploading anything
        self._leechers = struct.unpack_from("!i", raw_response, offset)[0]

        offset = offset + 4
        # seeders : the peers uploading the file
        self._seeders = struct.unpack_from("!i", raw_response, offset)[0]

        offset = offset + 4
        # obtains the peers list of (peer IP, peer port)
        self.peers_list = []
        while offset != len(raw_response):
            # raw data of peer IP, peer port
            raw_peer_data = raw_response[offset: offset + 6]

            # extract the peer IP address
            peer_ip = ".".join(str(int(a)) for a in raw_peer_data[0:4])
            # extract the peer port number
            peer_port = raw_peer_data[4] * 256 + raw_peer_data[5]

            # append to IP, port tuple to peer list
            self.peers_list.append((peer_ip, peer_port))
            offset = offset + 6

    def _connection_request(self, connection_payload) -> str:
        # send the connection payload to the tracker
        self._tracker_sock.sendto(connection_payload, (self._tracker_url, self._tracker_port))
        # receive the raw connection data
        try:
            raw_connection_data, conn = self._tracker_sock.recvfrom(2048)
        except Exception as e:
            raise ErrUDPTracker(f'UDP tracker connection request failed, err ={e}')

        return self._parse_connection_response(raw_connection_data)

    def announce_request(self, announce_payload) -> bytes | None:
        raw_announce_data = None
        trails = 0
        while trails < 8:
            # try connection request after some interval of time
            try:
                self._tracker_sock.sendto(announce_payload, (self._tracker_url, self._tracker_port))
                # receive the raw announce data
                raw_announce_data, conn = self._tracker_sock.recvfrom(2048)
                break
            except Exception as e:
                logger.error(f"{self._tracker_url} failed announce request attempt {str(trails + 1)}, err = {e}")
            trails = trails + 1
        return raw_announce_data

    def _parse_connection_response(self, raw_connection_data) -> str:
        # check if it is less than 16 bytes
        if len(raw_connection_data) < 16:
            raise ErrUDPTracker('UDP tracker wrong response length of connection ID !')

        # extract the reponse action : first 4 bytes
        action = struct.unpack_from("!i", raw_connection_data)[0]
        # error response from tracker
        if action == 0x3:
            e = struct.unpack_from("!s", raw_connection_data, 8)
            raise ErrUDPTracker('UDP tracker response error : ' + str(e))

        # extract the response transaction id : next 4 bytes
        transaction_id = struct.unpack_from("!i", raw_connection_data, 4)[0]
        # compare the request and response transaction id
        if transaction_id != self._transaction_id:
            raise ErrUDPTracker('UDP tracker wrong response transaction ID !')

        # extract the response connection id : next 8 bytes
        connection_id = struct.unpack_from("!q", raw_connection_data, 8)[0]
        return connection_id

    def _build_connection_payload(self) -> bytes:
        req_buffer = struct.pack("!q", self._connection_id)  # first 8 bytes : connection_id
        req_buffer += struct.pack("!i", self._action)  # next 4 bytes  : action
        req_buffer += struct.pack("!i", self._transaction_id)  # next 4 bytes  : transaction_id
        return req_buffer

    def _build_announce_payload(self) -> bytes:
        # action = 1 (announce)
        self._action = 0x1
        # first 8 bytes connection_id
        announce_payload = struct.pack("!q", self._connection_id)
        # next 4 bytes is action
        announce_payload += struct.pack("!i", self._action)
        # next 4 bytes is transaction id
        announce_payload += struct.pack("!i", self._transaction_id)
        # next 20 bytes the info hash string of the torrent
        announce_payload += struct.pack("!20s", self._request_parameters['info_hash'])
        # next 20 bytes the peer_id
        announce_payload += struct.pack("!20s", self._request_parameters['peer_id'])
        # next 8 bytes the number of bytes downloaded
        announce_payload += struct.pack("!q", self._request_parameters['downloaded'])
        # next 8 bytes the left bytes
        announce_payload += struct.pack("!q", self._request_parameters['left'])
        # next 8 bytes the number of bytes uploaded
        announce_payload += struct.pack("!q", self._request_parameters['uploaded'])
        # event 2 denotes start of downloading
        announce_payload += struct.pack("!i", 0x2)
        # your IP address, set this to 0 if you want the tracker to use the sender
        announce_payload += struct.pack("!i", 0x0)
        # some random key
        announce_payload += struct.pack("!i", int(random.randrange(0, 255)))
        # number of peers require, set this to -1 by default
        announce_payload += struct.pack("!i", -1)
        # port on which response will be sent
        announce_payload += struct.pack("!H", self._request_parameters['port'])
        # extension is by default 0x2 which is request string
        # announce_payload += struct.pack("!H", 0x2)
        return announce_payload

    @staticmethod
    def parse_tracker_url(tracker_url) -> (str, str):
        domain_url = tracker_url[6:].split(':')
        udp_tracker_url = domain_url[0]
        udp_tracker_port = int(domain_url[1].split('/')[0])
        return udp_tracker_url, udp_tracker_port


class HTTPTracker(BaseTraker):
    def __init__(self, metadata: TorrentMetadata, tracker_url: str):
        super().__init__(metadata)
        self.tracker_url = tracker_url

    def information_request(self):
        try:
            client = httpx.Client()
            raw_response = client.get(self.tracker_url, params=self._request_parameters, timeout=5)
            # decode the bencoded dictionary to python ordered dictionary
            raw_dict = bencodepy.decode(raw_response.content)
            # parse the dictionary containing raw data
            self._parse_response(raw_dict)
        except Exception as e:
            raise ErrHttpTracker(f"{self.tracker_url} connection failed, err={e}")

    def _parse_response(self, raw_response):
        if b'interval' in raw_response:
            self.interval = raw_response[b'interval']

        # list of peers form the participating the torrent
        if b'peers' in raw_response:
            self.peers_list = []
            # extract the raw peers data
            raw_peers_data = raw_response[b'peers']
            # create a list of each peer information which is of 6 bytes
            raw_peers_list = [raw_peers_data[i: 6 + i] for i in range(0, len(raw_peers_data), 6)]
            # extract all the peer id, peer IP and peer port
            for raw_peer_data in raw_peers_list:
                # extract the peer IP address
                peer_ip = ".".join(str(int(a)) for a in raw_peer_data[0:4])
                # extract the peer port number
                peer_port = raw_peer_data[4] * 256 + raw_peer_data[5]
                # append the (peer IP, peer port)
                self.peers_list.append((peer_ip, peer_port))

        # number of peers with the entire file aka seeders
        if b'complete' in raw_response:
            self.complete = raw_response[b'complete']

        # number of non-seeder peers, aka "leechers"
        if b'incomplete' in raw_response:
            self.incomplete = raw_response[b'incomplete']

        # tracker id must be sent back by the user on announcement
        if b'tracker id' in raw_response:
            self.tracker_id = raw_response[b'tracker id']
