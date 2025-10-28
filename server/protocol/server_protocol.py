# protocol/server_protocol.py
import struct
import uuid
from dataclasses import dataclass
from typing import Optional, Tuple
from data.db import Database

# Constants
CLIENT_HEADER_SIZE = 16 + 1 + 2 + 4  # id(16), ver(1), code(2 LE), size(4 LE)
SERVER_VERSION = 2
CLIENT_VERSION_SUPPORTED = 1

# Codes
CODE_REGISTRATION_REQ = 600
CODE_REGISTRATION_OK  = 2100
CODE_ERROR            = 9000

CODE_CLIENTS_LIST_REQ = 601
CODE_CLIENTS_LIST_OK  = 2101

CODE_SEND_MESSAGE_REQ  = 603
CODE_SEND_MESSAGE_OK   = 2103

CODE_PULL_WAITING_REQ  = 604
CODE_PULL_WAITING_OK   = 2104

# Payload sizes for registration
REG_NAME_LEN = 255
REG_PUBKEY_LEN = 160
REG_PAYLOAD_LEN = REG_NAME_LEN + REG_PUBKEY_LEN

ENTRY_UUID_LEN = 16
ENTRY_NAME_LEN = 255
ENTRY_TOTAL = ENTRY_UUID_LEN + ENTRY_NAME_LEN  # 271

CODE_PUBLIC_KEY_REQ   = 602
CODE_PUBLIC_KEY_OK    = 2102
PUBKEY_RESP_KEY_LEN   = 160  # response key length per spec

@dataclass
class ClientRequest:
    client_id: bytes  # 16 bytes
    version: int
    code: int
    payload: bytes

@dataclass
class ServerResponse:
    version: int
    code: int
    payload: bytes

def read_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from a socket (or raise)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed while reading")
        buf.extend(chunk)
    return bytes(buf)

def read_client_request(sock) -> ClientRequest:
    header = read_exact(sock, CLIENT_HEADER_SIZE)
    client_id, ver, code, size = struct.unpack("<16sBHI", header)
    payload = read_exact(sock, size) if size > 0 else b""
    return ClientRequest(client_id=client_id, version=ver, code=code, payload=payload)

def build_server_response(code: int, payload: bytes = b"") -> bytes:
    header = struct.pack("<BHI", SERVER_VERSION, code, len(payload))
    return header + payload

def handle_registration(db: Database, payload: bytes) -> ServerResponse:
    if len(payload) != REG_PAYLOAD_LEN:
        return ServerResponse(SERVER_VERSION, CODE_ERROR, b"")

    name_raw = payload[:REG_NAME_LEN]
    pub_raw  = payload[REG_NAME_LEN:REG_NAME_LEN+REG_PUBKEY_LEN]

    # ASCII, trim trailing NULs/space
    username = name_raw.rstrip(b"\x00 ").decode("ascii", errors="ignore")
    public_key = pub_raw.rstrip(b"\x00 ").decode("ascii", errors="ignore")

    # Check username existence
    if db.username_exists(username):
        return ServerResponse(SERVER_VERSION, CODE_ERROR, b"")

    # Create UUID and store
    uid = uuid.uuid4().bytes  # 16 bytes
    db.insert_client_with_uuid(username=username, public_key=public_key, unique_id_bytes=uid)

    return ServerResponse(SERVER_VERSION, CODE_REGISTRATION_OK, uid)

def handle_clients_list(db: Database, requester_uuid: bytes) -> ServerResponse:
    # Build payload: repeating (16 bytes uuid + 255 bytes name (ASCII, NUL-terminated, padded))
    try:
        rows = db.get_clients_excluding_uuid(requester_uuid)
        parts = []
        for uid_bytes, username in rows:
            if uid_bytes is None or len(uid_bytes) != 16:
                # skip malformed rows silently
                continue
            # 16 bytes UUID
            parts.append(uid_bytes)
            # 255 bytes name (ASCII, NUL-terminated, padded)
            name_bytes = username.encode("ascii", errors="ignore")
            name_field = bytearray(ENTRY_NAME_LEN)
            n = min(len(name_bytes), ENTRY_NAME_LEN - 1)  # leave space for '\0'
            name_field[:n] = name_bytes[:n]
            name_field[n] = 0
            parts.append(bytes(name_field))
        payload = b"".join(parts)
        return ServerResponse(SERVER_VERSION, CODE_CLIENTS_LIST_OK, payload)
    except Exception:
        return ServerResponse(SERVER_VERSION, CODE_ERROR, b"")

def handle_send_message(db: Database, requester_uuid: bytes, payload: bytes) -> ServerResponse:
    # Payload: destClientId(16) + msgType(1) + contentSize(4 LE) + content
    if len(payload) < 16 + 1 + 4:
        return ServerResponse(SERVER_VERSION, CODE_ERROR, b"")
    dest_uuid = payload[:16]
    msg_type = payload[16]
    content_size = struct.unpack("<I", payload[17:21])[0]
    if content_size < 0 or len(payload) != 16 + 1 + 4 + content_size:
        return ServerResponse(SERVER_VERSION, CODE_ERROR, b"")
    content = payload[21:]

    to_rowid = db.get_rowid_by_uuid(dest_uuid)
    from_rowid = db.get_rowid_by_uuid(requester_uuid)
    if to_rowid is None or from_rowid is None:
        return ServerResponse(SERVER_VERSION, CODE_ERROR, b"")

    mid = db.save_message(to_rowid, from_rowid, int(msg_type), content)
    # Response payload: ClientID(16 dest) + MessageID(4 LE)
    resp = dest_uuid + struct.pack("<I", mid)
    return ServerResponse(SERVER_VERSION, CODE_SEND_MESSAGE_OK, resp)

def handle_pull_waiting(db: Database, requester_uuid: bytes) -> ServerResponse:
    to_rowid = db.get_rowid_by_uuid(requester_uuid)
    if to_rowid is None:
        return ServerResponse(SERVER_VERSION, CODE_ERROR, b"")

    rows = db.get_waiting_messages_for(to_rowid)
    parts = []
    for msg_id, from_rowid, msg_type, content in rows:
        from_uuid = db.get_uuid_by_rowid(from_rowid)
        if not from_uuid:
            continue
        parts.append(from_uuid)                  # 16
        parts.append(struct.pack("<I", msg_id))  # 4
        parts.append(struct.pack("<B", int(msg_type))) # 1
        parts.append(struct.pack("<I", len(content)))  # 4
        parts.append(content)                    # N
    payload = b"".join(parts)
    return ServerResponse(SERVER_VERSION, CODE_PULL_WAITING_OK, payload)

def handle_public_key_request(db: Database, payload: bytes) -> ServerResponse:
    # payload must be exactly 16 bytes: target client's unique ID
    if len(payload) != 16:
        return ServerResponse(SERVER_VERSION, CODE_ERROR, b"")
    target_uid = payload
    pk = db.get_public_key_by_uuid(target_uid)
    if pk is None:
        return ServerResponse(SERVER_VERSION, CODE_ERROR, b"")
    pk_bytes = pk.encode("ascii", errors="ignore")
    field = bytearray(PUBKEY_RESP_KEY_LEN)
    n = min(len(pk_bytes), PUBKEY_RESP_KEY_LEN)
    field[:n] = pk_bytes[:n]
    resp_payload = target_uid + bytes(field)
    return ServerResponse(SERVER_VERSION, CODE_PUBLIC_KEY_OK, resp_payload)
