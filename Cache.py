import redis
import secrets
import ast
import datetime
from ConfigReader import ConfigReader


class Cache:
    def __init__(self, key_storage_path, config, db=0):
        """
        Simple redis cache wrapper

        Parameters:
            - key_storage_path (str) :: The path where peers keys are to be stored
            - config (dict) :: The config dictionary
            - db (int) :: Redis db, pretty much always use 0 
        """
        self.db = db
        self.redis = redis.Redis(host="localhost", port=6379, db=db)
        self.conf = config
        self.keystore = key_storage_path
        self.db_prefix = "bp_"

    def new_verification_token(self, peer_id):
        """
        Creates a new verification token and connection id and logs it to memory. 
        Returns false if the max number of active connections is exceeded

        Parameters:
            - peer_id :: The ID of the Peer trying to connect

        Returns:
            - connection_id :: The ID for the websocket connection to be used by the
                               peer
            - verification_token :: The token that is to be encrypted using the peers
                                    public key by the service
            - False :: Returns false if the max number of connections is reached as defined
            in the microservice.conf file
        """
        # check to see if we're already connected to a peer
        conns = self.get_active_connections()
        if conns:
            if len(conns) >= self.conf['max_num_connections']:
                return False

        connection_id = secrets.token_urlsafe(16)
        verification_token = secrets.token_bytes(64)
        now = datetime.datetime.now()
        entry = {
            "connection_id": connection_id,
            "verification_token": verification_token,
            "id": peer_id,
            "created_on": datetime.datetime.strftime(now, "%Y-%m-%d %H:%M:%S"),
            "active": True
        }

        # append the entry to the verification table
        self._append(self.db_prefix+"verification_tokens", entry)
        return entry

    def verify_connection(self, peer_id, connection_id, verification_token):
        """
        Checks the verification_tokens table and ensures the peer is allowed to connect to the 
        service or not

        Returns:
            - bool :: True if the peer checks out, False if it doesn't
        """

        verification_table = self._get(self.db_prefix+"verification_tokens")
        if not verification_table:
            return False

        for v in verification_table:
            if v['id'] == peer_id and v['connection_id'] == connection_id and v['verification_token'] == verification_token:
                return True
        return False

    def log_key(self, peer_id, key_identifier):
        """
        Logs a peers key given the peer id and the key identifier produced by the KeyAuthenticator

        Parameters:
            - peer_id (str) :: The peer_id to log
            - key_identifier (str) :: The randomized key identifier

        Returns:
            - is_logged (bool) :: True if the value has been logged, false if it hasn't
        """
        log = {
            "id": peer_id,
            "key_identifier": key_identifier
        }

        self._append("{}{}".format(self.db_prefix, "keystore"), log)
        return True

    # TODO Prolly merge these two functions since right now they are pretty much identical
    def get_peer_from_key_ident(self, key_identifier):
        """
        Resolves the key identifier and returns the peer id it belongs to. Returns False if no 
        key identifier is found
        """
        all_keys = self._get("{}{}".format(self.db_prefix, "keystore"))
        if not all_keys:
            return False

        for key in all_keys:
            if key['key_identifier'] == key_identifier:
                return key['id']
        return False

    def get_key_identity_from_peer(self, peer_id):
        """
        Gets the key identity given a peer id
        """
        all_keys = self._get("{}{}".format(self.db_prefix, "keystore"))
        if not all_keys:
            return False
        for key in all_keys:
            if key['id'] == peer_id:
                return key['key_identifier']
        return False

    def get_active_connections(self):
        conns = self._get("{}{}".format(
            self.db_prefix, "active_connections"))
        return conns

    def _serialize_dict(self, input_dict):
        """
        Takes a dictionary and returns a byte representation of it to stored in the 
        in memory redis database

        Parameters:
            - input_dict :: A dictionary to serialize

        Returns:
            - serialized_dict (bytes) :: A bytes object
        """
        serialized_dict = str(input_dict)
        serialized_dict = str.encode(serialized_dict)
        return serialized_dict

    def _deserialize_dict(self, serialized_dict):
        if type(serialized_dict) != bytes:
            raise Exception("Bytes expected for deserialization")
        deserialized = ast.literal_eval(serialized_dict.decode("utf-8"))
        return deserialized

    def _get(self, key):
        """
        Gets a key from redis, and then formats it back into a dict from its bytes representation

        Parameters:
            key (str) :: The key to get a value for

        Returns:
            val (dict|None) :: If a value exists it is decoded back into a dictionary
        """

        val = self.redis.get(key)

        if not val:
            return val

        val = ast.literal_eval(val.decode("utf-8"))
        return val

    def _del(self, key):
        """
        Deletes a key from the redis cache

        Returns:
            - 1 if the key was deleted, 0 if the key wasn't or didn't exist
        """
        return self.redis.delete(key)

    def _set(self, key, val):
        """
        Sets a key with value val 

        Parameters:
            - key (str) :: The key to set
            - val (any) :: the value to attribute to the key
        """
        if type(val) == dict or type(val) == list:
            # serialize the dict beforehand
            val = self._serialize_dict(val)

        if type(val) == str:
            val = val.encode("utf-8")

        # push to the database
        self.redis.set(key, val)
        return True

    def _append(self, key, val):
        """
        Appends an item to the redis key 
        """
        cache = self._get(key)
        if not cache:
            self._set(key, [val])
            return True
        else:
            cache.append(val)
            self._set(key, cache)
            return True
