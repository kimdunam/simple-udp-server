

# Standard libraries
import argparse
import logging

# User-defined libraries
from protocols import UDPClient
from utils import parse_arguments


def main():
    args = parse_arguments()
    logging.basicConfig(level=args.logging)

    client = UDPClient(addr=args.addr, port=args.port)

    if args.signup:
        if not args.username or not args.password:
            logging.error("Username and password are required for signup")
            return
        client.signup(username=args.username, password=args.password)

    if args.signin:
        if not args.username or not args.password:
            logging.error("Username and password are required for signin")
            return
        client.signin(username=args.username, password=args.password)

    if args.download:
        if not args.filename:
            logging.error("Filename is required for download image")
            return
        client.request_content(filename=args.filename)
    

if __name__ == "__main__":
    main()
