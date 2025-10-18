# models/client.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class Client:
    ID: Optional[int]
    username: str
    publicKey: Optional[str]
    lastSeen: Optional[str]  # ISO-8601 string
