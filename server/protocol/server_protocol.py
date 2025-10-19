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

# Payload sizes for registration
REG_NAME_LEN = 255
REG_PUBKEY_LEN = 150
REG_PAYLOAD_LEN = REG_NAME_LEN + REG_PUBKEY_LEN

ENTRY_UUID_LEN = 16
ENTRY_NAME_LEN = 255
ENTRY_TOTAL = ENTRY_UUID_LEN + ENTRY_NAME_LEN  # 271

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
