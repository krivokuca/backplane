import ast
import os
import urllib.parse as urlparse
import asyncio
import requests
import time
import websocket
import zlib
from Cache import Cache
from KeyAuthentication import KeyAuthentication
from DataModels import WebsocketPacket
from utils import bytes_to_datamodel, datamodel_to_bytes


class Client:
    """
    The Client implementation of Backplane.
    """
    BACKPLANE_CERT_FILE = os.environ.get('BACKPLANE_CERT')
    BACKPLANE_PRIV_KEY = os.environ.get('BACKPLANE_PRIV')
    BACKPLANE_PUB_KEY = os.environ.get('BACKPLANE_PUB')
    BACKPLANE_KEY_PATH = os.environ.get('BACKPLANE_KEYSTORE')

    def __init__(self, config_path):

        self.config_path = config_path

        with open(self.config_path, "r") as f:
            self.config = ast.literal_eval(f.read())

        self.peers = [x['id'] for x in self.config['peers']]

        with open(self.BACKPLANE_CERT_FILE, "rb") as f:
            self.cert = f.read()

        self.cache = Cache(self.BACKPLANE_KEY_PATH, self.config)
        self.key_auth = KeyAuthentication(
            self.config, self.BACKPLANE_PUB_KEY, self.BACKPLANE_PRIV_KEY, self.BACKPLANE_KEY_PATH, self.cert)

        # websocket stuff. On connection, the websocket client is appended to self.ws. Each time a message is to
        # be polled
        self.connection_id = False
        self.peer_id = None
        self.ws = False

    def connect(self, peerid):
        """
        Establishes the handshake with the hosting server. If the handshake is successful then the connection
        is opened and appended to self.ws. The connection parameters are also added to the in memory storage
        via the Cache class

        Parameters:
            - peerid (str) :: the peer to connect to

        Returns:
            - is_successful_connection (bool) :: True if the Client was successfully able to connect and mount a
                                                 connection, False if they weren't

        """

        if peerid not in self.peers:
            raise Exception("Peer with id `{}` does not exist".format(peerid))

        peer_obj = {}
        for peer_config in self.config['peers']:
            if peer_config['id'] == peerid:
                peer_obj = peer_config
                break

        # check to see if the max number of connections is already achieved
        num_conns = self.cache.get_active_connections()
        if num_conns and len(num_conns) > self.config['settings']['max_num_connections']:
            raise Exception(
                "Max number of connections already reached. Cannot connect to peer {}".format(peerid))

        signed_payload = self.key_auth.sign_cert()
        signed_payload = self.key_auth.encode_b64(signed_payload)
        public_key = self.key_auth.encode_b64(self.key_auth.keys['public'])
        id = self.config['self']['id']
        json_payload = {
            "id": id,
            "public_key": public_key,
            "signed_payload": signed_payload
        }

        # Resolve the peers IP here. If both the peer and the client have the same geoname then it will
        # default to connecting via private LAN.
        peer_ip = None
        peer_port = None
        if peer_obj['geoname'] == self.config['self']['geoname']:
            peer_ip = peer_obj['networking']['private']['ip']
            peer_port = peer_obj['networking']['private']['port']
        else:
            peer_ip = peer_obj['networking']['public']['ip']
            peer_port = peer_obj['networking']['public']['port']

        handshake_url = "http://{}:{}/handshake".format(peer_ip, peer_port)

        handshake_response = self._handle_connection(
            handshake_url, 'post', json_payload)

        if not handshake_response:
            raise Exception("Could not connect to peer `{}`".format(peerid))

        if not handshake_response['success']:
            raise Exception(handshake_response['message'])

        peer_public_key = self.key_auth.decode_b64(
            handshake_response['public_key'])

        if not self.cache.get_key_identity_from_peer(peerid):
            key_ident = self.key_auth.store_peer_publickey(peer_public_key)
            self.cache.log_key(peerid, key_ident)

        # decrypt the verification token
        self.connection_id = handshake_response['connection_id']
        encrypted_token = self.key_auth.decode_b64(
            handshake_response['verification_token'])

        decrypted_token = self.key_auth.decrypt(encrypted_token)
        if not decrypted_token:
            raise Exception(
                "Error decrypting verification token. Handshake failed.")

        verification_token = self.key_auth.encode_b64(decrypted_token)

        # format the websocket URL
        websocket_url = "ws://{}:{}/stream?id={}&connectionid={}&verificationtoken={}".format(
            peer_ip, peer_port, id, self.connection_id, urlparse.quote_plus(verification_token))

        # attempt to initalize the websocket connection
        attempt = self._init_websocket(websocket_url)

        if not attempt:
            raise Exception(
                "Could not connect url `{}` :: Websocket might be busy".format(websocket_url))

        else:
            # send the initalization request
            print("connected!")
            return True

    def poll(self, func):
        """
        Decorator. The function this wraps must return a WebsocketPacket or an Exception will be thrown.
        Note* All encryption and compression is to be done in the wrapper depending on the is_encrypted and the
        is_compressed flags being True or False

        Returns:
            - Exception | WebsocketPacket :: If the polling time is reached or if the websocket is unresponsive then an
                                  exception is thrown, else a resulting DataModel is returned as a Dict
        """

        if not self.ws:
            raise Exception(
                "Websocket connection has not been established, cannot poll")

        def decorator():

            datamodel = func()
            if not isinstance(datamodel, WebsocketPacket):
                raise Exception(
                    "Function being wrapped must return WebsocketPacket")

            if datamodel.is_encrypted:
                raise Exception(
                    "Websocket packet Encryption not yet supported")

            if not datamodel.connection_id:
                datamodel.connection_id = self.connection_id

            if not datamodel.id:
                datamodel.id = self.peer_id

            byte_payload = datamodel_to_bytes(
                datamodel, compress=datamodel.is_compressed)

            self.ws.send_binary(byte_payload)
            reply_bytes = self.ws.recv()
            reply_data = bytes_to_datamodel(
                reply_bytes, datamodel.is_compressed)

            return reply_data

        return decorator

    def _init_websocket(self, url):
        """
        Attempts to bind the websocket connection to self.ws

        Parameters:
            - url (str) :: The URL to connect to

        Returns:
            - has_connected | Exception :: True will be returned if the connection has been instantiated, False if the server
                                           has too many connections or an Exception will be thrown
        """

        try:
            self.ws = websocket.create_connection(url)
            return True
        except Exception as e:
            print(e)
            raise Exception(
                "Could not connect to the websocket (url: {}".format(url))

    def _handle_connection(self, url, req_type, json_payload=False):
        """
        Response wrapper that handles all the errors that can arise from connecting to an offline peer.

        Parameters:
            - url (str) :: The url to connect to
            - req_type (str) :: Either 'post' for post requests or 'get' for a get requests
            - json_payload (dict) :: Optional, if set then the json_payload will be sent as a JSON object with
                                     the post request

        Returns:
            - response (dict) :: The JSON response from the server. Note, if the response is not in JSON then this
                                 function will raise an Exception
        """

        if req_type not in ['post', 'get']:
            raise Exception("Request required to be post or get")

        if req_type == 'get' and json_payload:
            raise Exception("Cannot send JSON payload using GET request")

        response = None
        try:
            if req_type == 'get':
                response = requests.get(url)

            elif req_type == 'post':
                if json_payload:
                    response = requests.post(url, json=json_payload)
                else:
                    response = requests.post(url)

            return response.json()

        except Exception as e:
            print(e)
            return False
