# models/message.py
from dataclasses import dataclass
from typing import Optional

@dataclass
class Message:
    ID: Optional[int]
    toClient: Optional[int]
    fromClient: int
    type: str
    content: str
