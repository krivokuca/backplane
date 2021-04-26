from datetime import datetime
from pydantic import BaseModel
from typing import Optional


class HandshakeRequest(BaseModel):
    """
    The primary handkshake request establishes the identity of the peer thats trying to connect with this 
    service. The peer sends over a signed payload (signed with their private key) as well as their public
    key. The service then verifies the signed payload against its own and sends back the same HandshakeRequest
    with its own public_key and signed_payload for the peer to verify. The second HandshakeRequest that the
    server responds to will be continuation = True, otherwise continuation = False
    """

    id: str
    continuation: Optional[bool] = None
    verification_token: Optional[str] = None
    connection_id: Optional[str] = None
    success: Optional[bool] = None
    msg: Optional[str] = None
    public_key: str
    signed_payload: str


class WebsocketRequestHeader(BaseModel):
    """
    Model used when a peer is connecting to the server after the HandshakeRequest response is made by the service.
    The signed_verification_token is the verification_token returned by the service, encrypted with the services
    public key by the peer.
    """
    id: str
    connection_id: str
    signed_verification_token: bytes


class WebsocketPacket(BaseModel):
    """
    Standardized format for transmitting an Event across the websocket to the client/server
    """
    id: Optional[str] = None
    connection_id: Optional[str] = None
    timestamp: Optional[int] = None
    is_encrypted: bool
    is_compressed: bool
    event: str
    polling_timeout: int
    event_data: dict


class CloseRequest(BaseModel):
    id: str


class ActiveConnectionsTable(BaseModel):
    id: str
    created_on: datetime
    connection_id: str


class VerificationTokensTable(BaseModel):
    id: str
    verification_token: str
    connection_id: str
    created_on: datetime
    active: bool


class TestVal(BaseModel):
    msg: str
    id: Optional[str] = None
