# main.py
from server_socket import PortServer
from file_config import PortConfig

def main():
    port = PortConfig().get_port()
    server = PortServer(port=port)
    server.run()

if __name__ == "__main__":
    main()
