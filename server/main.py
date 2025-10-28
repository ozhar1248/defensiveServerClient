from file_config import PortConfig
from network.server_socket import PortServer

def main():
    port = PortConfig().get_port()
    server = PortServer(port=port)
    server.run()

if __name__ == "__main__":
    main()
