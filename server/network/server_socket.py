# network/server_socket.py
import socket
import threading
from data.db import Database

class ClientHandler(threading.Thread):
    def __init__(self, conn: socket.socket, addr):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr  # (ip, port)

    def run(self):
        username = f"{self.addr[0]}:{self.addr[1]}"  # placeholder until we add auth
        print(f"[+] Client connected: {username}", flush=True)

        # Open a DB connection for this thread
        with Database() as db:
            client_id = db.upsert_client(username=username)

            try:
                with self.conn:
                    while True:
                        data = self.conn.recv(4096)
                        if not data:
                            print(f"[-] Client disconnected: {username}", flush=True)
                            break

                        msg = data.decode("utf-8", errors="replace").rstrip("\r\n")
                        print(f"Message received from {username}: {msg}", flush=True)

                        # Store message (from this client -> no 'to' specified yet)
                        db.insert_message(to_client_id=None, from_client_id=client_id,
                                          msg_type="text", content=msg)
                        db.update_last_seen(client_id)

                        # Ack back to client
                        self.conn.sendall(f"Your message '{msg}' was accepted\n".encode("utf-8"))
            except Exception as e:
                print(f"[!] Error with {username}: {e}", flush=True)

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
