# network/server_socket.py
import socket
import threading
from data.db import Database
from protocol.server_protocol import (
    read_client_request, build_server_response,
    CODE_REGISTRATION_REQ, CODE_CLIENTS_LIST_REQ, CODE_PUBLIC_KEY_REQ,
    CODE_SEND_MESSAGE_REQ, CODE_PULL_WAITING_REQ,
    CODE_ERROR,
    handle_registration, handle_clients_list, handle_public_key_request,
    handle_send_message, handle_pull_waiting
)

class ClientHandler(threading.Thread):
    def __init__(self, conn: socket.socket, addr):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr

    def run(self):
        print(f"[+] Client connected: {self.addr}", flush=True)
        with Database() as db, self.conn:
            try:
                while True:
                    try:
                        req = read_client_request(self.conn)
                    except ConnectionError:
                        print(f"[-] Client disconnected: {self.addr}", flush=True)
                        break

                    if req.code == CODE_REGISTRATION_REQ:
                        resp = handle_registration(db, req.payload)
                    elif req.code == CODE_CLIENTS_LIST_REQ:
                        resp = handle_clients_list(db, req.client_id)
                    elif req.code == CODE_PUBLIC_KEY_REQ:
                        resp = handle_public_key_request(db, req.payload)
                    elif req.code == CODE_SEND_MESSAGE_REQ:
                        resp = handle_send_message(db, req.client_id, req.payload)
                    elif req.code == CODE_PULL_WAITING_REQ:
                        resp = handle_pull_waiting(db, req.client_id)
                    else:
                        resp = type("R", (), {"version":2,"code":CODE_ERROR,"payload":b""})()
                    self.conn.sendall(build_server_response(resp.code, resp.payload))

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
