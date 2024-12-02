

# Standard modules
import logging

# User-defined modules
from protocols import UDPServer
from utils import parse_arguments


def main():
    args = parse_arguments()
    logging.basicConfig(level=args.logging)

    server = UDPServer(addr=args.addr, port=args.port)
    server.run()

if __name__ == "__main__":
    main()