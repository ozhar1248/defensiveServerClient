# file_config.py
from pathlib import Path

DEFAULT_PORT = 1357
FILENAME = "myport.info"

class PortConfig:
    """Reads TCP port from a file next to the entry script. Falls back to DEFAULT_PORT."""
    def __init__(self, base_dir: Path | None = None):
        # Default: folder of the running script
        self.base_dir = base_dir or Path(__file__).resolve().parent
        self.path = self.base_dir / FILENAME

    def get_port(self) -> int:
        if not self.path.exists():
            print(f"[warn] '{FILENAME}' not found in {self.base_dir}. Using default {DEFAULT_PORT}.")
            return DEFAULT_PORT
        try:
            text = self.path.read_text(encoding="utf-8").strip()
            return int(text)
        except Exception as e:
            print(f"[warn] Failed reading '{self.path}': {e}. Using default {DEFAULT_PORT}.")
            return DEFAULT_PORT
