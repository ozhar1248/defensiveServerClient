# server_socket.py
import socket
import threading

class ClientHandler(threading.Thread):
    def __init__(self, conn: socket.socket, addr):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr

    def run(self):
        print(f"[+] Client connected: {self.addr}", flush=True)
        try:
            with self.conn:
                while True:
                    data = self.conn.recv(4096)
                    if not data:
                        print(f"[-] Client disconnected: {self.addr}", flush=True)
                        break
                    msg = data.decode("utf-8", errors="replace").rstrip("\r\n")
                    print(f"Message received from {self.addr}: {msg}", flush=True)
                    self.conn.sendall(f"Your message '{msg}' was accepted\n".encode("utf-8"))
        except Exception as e:
            print(f"[!] Error with {self.addr}: {e}", flush=True)

class PortServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 1357, backlog: int = 50):
        self.host, self.port, self.backlog = host, port, backlog
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(self.backlog)

    def run(self):
        print(f"Server listening on {self.host}:{self.port}", flush=True)
        try:
            while True:
                conn, addr = self.sock.accept()
                ClientHandler(conn, addr).start()
        except KeyboardInterrupt:
            print("\nShutting down server...", flush=True)
        finally:
            self.sock.close()
