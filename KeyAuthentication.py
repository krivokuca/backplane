import base64
import os
import secrets

from cryptography.hazmat.backends import \
    default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import \
    serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class KeyAuthentication:
    def __init__(self, config, public_key, private_key, keystore_path, cert):
        """
        The KeyAuthentication class is responsible for verifying incoming connections, signing certs and 
        encrypting and decrypting incoming certificate payloads or sensitive data to be transfered over the
        websocket

        Parameters:
            - config :: The config dictionary defined in `microservice.conf`
            - public_key :: Path to the public key
            - private_key :: Path to the private key
            - keystore_path :: The path to a folder where the peers keys will be saved
            - The certificate (bytes)


        """
        if not cert or type(cert) != bytes:
            raise Exception("Certificate must be in bytes")
        self.config = config
        self.priv_path = private_key
        self.pub_path = public_key
        self.peer_keystore = keystore_path
        self.keys = {
            "private": None,
            "public": None
        }
        self.cert = cert

        # attempt to load the keys into memory
        if os.path.isfile(self.priv_path):
            self.keys['private'] = self.deserialize_key(self.priv_path)

        if os.path.isfile(self.pub_path):
            self.keys['public'] = self.deserialize_key(self.pub_path)

    def create_keypair(self, key_size=4096):
        """
        Creates a new key pair and replaces the keys in the self.priv_path and self.pub_paths with the new
        keys as well as overwriting the self.keys dict

        Returns:
            True 
        """
        private_key = rsa.generate_private_key(
            backend=crypto_default_backend(), public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
        pem = private_key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption()
        )

        pub = public_key.public_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if os.path.isfile(self.priv_path):
            os.remove(self.priv_path)

        with open(self.priv_path, 'wb') as f:
            f.write(pem)

        if os.path.isfile(self.pub_path):
            os.remove(self.pub_path)

        with open(self.pub_path, 'wb') as f:
            f.write(pub)

        self.keys['public'] = pem
        self.keys['private'] = pub

        return True

    def store_peer_publickey(self, peer_public_bytes):
        """
        Stores the peers public key 

        Parameters:
            - peer_public_bytes (bytes) :: The byte representation of the public key
        Returns:
            - key_identifier (str) :: A random 32 byte string identifying the peer. This is also the 
                                      filename of the peer token.
        """

        if type(peer_public_bytes) != bytes:
            raise Exception("Public key must be in bytes")

        key_identifier = secrets.token_hex(16)
        with open("{}{}".format(self.peer_keystore, key_identifier), "wb") as f:
            f.write(peer_public_bytes)

        return key_identifier

    def sign_cert(self):
        """
        This function attempts to sign the cert using the private key. Note* The private key must be loaded
        """

        if not self.keys['private']:
            raise Exception("Private key is not loaded")

        key = crypto_serialization.load_pem_private_key(
            self.keys['private'], password=None, backend=crypto_default_backend())
        signature = key.sign(self.cert, padding.PSS(mgf=padding.MGF1(
            hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return signature

    def verify_cert(self, encrypted_payload, public_key):
        """
        Attempts to verify a signed certificate using the public key, encrypted certificate and original
        certificate
        """
        if type(public_key) != bytes:
            raise Exception("Public key must be bytes")

        key = crypto_serialization.load_pem_public_key(
            public_key, backend=crypto_default_backend())
        try:
            key.verify(
                encrypted_payload,
                self.cert,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True

        except Exception as e:
            print(e)
            return False

    def encrypt(self, byte_object, byte_key=False):
        """
        Takes a byte_object of type bytes and encrypts it using the public key.

        Parameters:
            - byte_object (bytes) :: The bytestream to encrypt
            - byte_key (bytes) :: The key, in bytes to load. If False the services key will be 
                                  used by default

        Returns:
            - cipher (bytes) :: The encrypted content
        """
        if not self.keys['public'] and not byte_key:
            raise Exception(
                "Public key is not defined or set. It is required to encrypt messages")

        key_source = self.keys['public'] if not byte_key or type(
            byte_key) != bytes else byte_key

        public_key = crypto_serialization.load_pem_public_key(
            key_source, backend=crypto_default_backend())

        cipher = public_key.encrypt(
            byte_object,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return cipher

    def decrypt(self, encrypted_bytes, private_key_bytes=False):
        """
        Takes the encrypted bytes and attempts to decrypt them using the private key
        """

        if not self.keys['private'] and not private_key_bytes:
            raise Exception(
                "Private key is not defined or set. It is required to decrypt messages")

        key_source = self.keys['private'] if not private_key_bytes else private_key_bytes

        if type(key_source) != bytes:
            raise Exception("Private key must be of type bytes")

        private_key = crypto_serialization.load_pem_private_key(
            self.keys['private'], backend=crypto_default_backend(), password=None)

        unencrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return unencrypted

    def serialize_key(self, key, location):
        with open(location, 'wb') as f:
            f.write(key)

        return True

    def deserialize_key(self, location):
        """
        Returns bytes
        """
        with open(location, 'rb') as f:
            key = f.read()
        return key

    def public_encode_b64(self):
        """
        Returns the public key as an encoded base64 string
        """
        return self.encode_b64(self.keys['public'])

    def encode_b64(self, input_bytes):
        """
        Encodes bytes as a b64 string
        """
        try:
            encoded = base64.b64encode(input_bytes)
            return encoded.decode("utf-8")
        except Exception as e:
            return False

    def decode_b64(self, b64_str):
        """
        Takes a base64 encoded string and decodes it back into bytes
        """
        try:
            b64_str = b64_str.encode("utf-8")
            decoded = base64.b64decode(b64_str)
            return decoded
        except Exception as e:
            print("Fuck!", e)
            return False
