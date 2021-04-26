
import os
from copy import copy
import pymysql
import ast
from typing import Optional

import uvicorn
from fastapi import FastAPI, Query, Request, WebSocket, status

from Cache import Cache
from ConfigReader import ConfigReader
from DataModels import CloseRequest, HandshakeRequest, TestVal, WebsocketPacket
from EventHandler import EventHandler
from KeyAuthentication import KeyAuthentication
from dbutils.steady_db import connect
from utils import bytes_to_datamodel, datamodel_to_bytes

# Config stuff
app = FastAPI()

# CHANGE THIS TO YOUR CONFIG FILEPATH
BACKPLANE_CONFIG_PATH = '/path/to/microservice.conf'

BACKPLANE_CERT_FILE = os.environ.get('BACKPLANE_CERT')
BACKPLANE_PRIV_KEY = os.environ.get('BACKPLANE_PRIV')
BACKPLANE_PUB_KEY = os.environ.get('BACKPLANE_PUB')
BACKPLANE_KEY_PATH = os.environ.get('BACKPLANE_KEYSTORE')
BACKPLANE_DB_CONFIG = ast.literal_eval(os.environ.get("BACKPLANE_DB_CREDS"))


# test
if not BACKPLANE_CERT_FILE:
    raise Exception("Backplane certificate variable not set")
if not os.path.isfile(BACKPLANE_CERT_FILE):

    raise Exception("Backplane certificate not found")

with open(BACKPLANE_CERT_FILE, 'rb') as f:
    BACKPLANE_CERT = f.read()

CONFIG = ConfigReader(BACKPLANE_CONFIG_PATH).config
PEER_LIST = [x['id'] for x in CONFIG['peers']]

key_auth = KeyAuthentication(
    CONFIG, BACKPLANE_PUB_KEY, BACKPLANE_PRIV_KEY, BACKPLANE_KEY_PATH, BACKPLANE_CERT)

# instantiate the in memory cache and the sql db
cache = Cache(BACKPLANE_KEY_PATH, CONFIG, db=0)
database_connection = connect(
    creator=pymysql,
    host="localhost",
    user=BACKPLANE_DB_CONFIG['username'],
    password=BACKPLANE_DB_CONFIG['password'],
    database="vestra",
    autocommit=True,
    charset='utf8mb4',
    cursorclass=pymysql.cursors.DictCursor
)

events = EventHandler(BACKPLANE_CONFIG_PATH, database_connection)

if not key_auth.keys['private'] and not key_auth.keys['public']:
    print("[Backplane] Creating keypair for {}".format(
        CONFIG['self']['id']))

    keypair_success = key_auth.create_keypair()

    if not keypair_success:
        raise Exception("Error in keypair generation")


@app.post("/test")
async def test(req: TestVal):
    enc = key_auth.encrypt(req.msg.encode('utf-8'))

    dec = key_auth.decrypt(enc)

    return{
        "decrypted": dec
    }


@app.post("/handshake")
async def handshake(req: HandshakeRequest):
    if req.id not in PEER_LIST:
        return{
            "success": False,
            "msg": "Peer not in peer list"
        }

    req.public_key = key_auth.decode_b64(req.public_key)
    req.signed_payload = key_auth.decode_b64(req.signed_payload)
    if not req.public_key or not req.signed_payload:
        return{
            "success": False,
            "msg": "Malformed public_key or signed_payload issued"
        }
    # incoming request where we are the host and the requestee is the client
    verified = key_auth.verify_cert(req.signed_payload, req.public_key)
    if not verified:
        return {
            "success": False,
            "msg": "Certification Verification Failed"
        }

    # create a new connection_id/verification_token pair and save the peers token
    token = cache.new_verification_token(req.id)

    if not token:
        # we have maxed out the number of active connections
        return {
            "success": False,
            "msg": "Client has reached max_num_connections"
        }

    # encrypt the token using the peers public key
    encrypted_verification_token = key_auth.encrypt(
        token['verification_token'], req.public_key)

    encoded_verification_token = key_auth.encode_b64(
        encrypted_verification_token)

    # check to see if the peers key is already stored
    is_stored = cache.get_key_identity_from_peer(req.id)
    if not is_stored:
        key_file_ident = key_auth.store_peer_publickey(req.public_key)
        cache.log_key(req.id, key_file_ident)

    signature = key_auth.sign_cert()
    if not signature:
        return{
            "success": False,
            "msg": "Error signing cert"
        }

    signed_payload = key_auth.encode_b64(signature)
    if not signed_payload:
        return{
            "success": False,
            "msg": "Malformed response created. This error should never happen"
        }

    return{
        "success": True,
        "id": CONFIG['self']['id'],
        "public_key": key_auth.public_encode_b64(),
        "signed_payload": key_auth.encode_b64(signature),
        "continuation": True,
        "connection_id": token['connection_id'],
        "verification_token": encoded_verification_token
    }


@app.post("/bye")
async def close_connection(req: CloseRequest):
    return req


@app.websocket("/stream")
# websocket exceptions
# https://tools.ietf.org/html/rfc6455#section-7.4.1
# TODO :: debugging here
async def handle_websocket(
        websocket: WebSocket,
        id: Optional[str] = Query(None),
        connectionid: Optional[str] = Query(None),
        verificationtoken: Optional[str] = Query(None)):

    if not id or not connectionid or not verificationtoken:
        await websocket.close(code=status.WS_1002_PROTOCOL_ERROR)
        return False

    # the verification_token needs to be decrypted
    print(verificationtoken)
    verificationtoken = verificationtoken.strip()
    verification_token = key_auth.decode_b64(
        verificationtoken)

    if not verification_token:

        await websocket.close(code=status.WS_1002_PROTOCOL_ERROR)
        return False

    verified = cache.verify_connection(
        id, connectionid, verification_token)

    if not verified:
        await websocket.close(code=status.WS_1002_PROTOCOL_ERROR)
        return False

    await websocket.accept()

    while True:
        data = await websocket.receive_bytes()
        payload = bytes_to_datamodel(data)
        response_payload = events.handle_event(payload)

        response_bytes = datamodel_to_bytes(
            response_payload, response_payload.is_compressed)
        await websocket.send_bytes(response_bytes)


if __name__ == "__main__":
    """
    This is the main uvicorn instance that runs on the specified port and instantiates everything backplane related
    """

    uvicorn.run(app, port=CONFIG['self']['networking']['public']['port'], host=CONFIG['self']['networking']['private']['ip'],
                headers=[("server", "backplane")])
