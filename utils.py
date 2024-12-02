

# Standard libraries
import argparse
from typing import Optional, Tuple

# User-defined libraries
from constants import *


class Context:
    seq_slice = slice(1, 5)
    ack_slice = slice(5, 9)
    msg_slice = slice(9, None)

    def __init__(
        self,
        server_addr,
        server_port,
        client_addr,
        client_port,
        server_seq_num,
        client_seq_num,
    ):
        self._server_addr = server_addr
        self._server_port = server_port
        self._client_addr = client_addr
        self._client_port = client_port
        self._server_seq_num = server_seq_num
        self._client_seq_num = client_seq_num
        self._id = f"{server_addr}:{server_port}-{client_addr}:{client_port}"

    @property
    def id(self):
        return self._id
    @property
    def server_addr(self):
        return self._server_addr
    @property
    def server_port(self):
        return self._server_port
    @property
    def client_addr(self):
        return self._client_addr
    @property
    def client_port(self):
        return self._client_port
    @property
    def server_seq_num(self):
        return self._server_seq_num
    @property
    def client_seq_num(self):
        return self._client_seq_num

    def encapsulate(self, msg: str) -> bytes:
        seq = self._client_seq_num
        ack = self._server_seq_num

        packet = b''
        packet += FLAG_REQUEST.to_bytes(1, byteorder="big")
        packet += seq.to_bytes(4, byteorder="big")
        packet += ack.to_bytes(4, byteorder="big")
        packet += msg.encode("ascii")
        return packet

    def decapsulate(self, msg: bytes) -> str:
        flag = msg[0]
        seq = int.from_bytes(msg[self.seq_slice], byteorder="big")
        ack = int.from_bytes(msg[self.ack_slice], byteorder="big")
        
        # Update sequence numbers
        self._server_seq_num = ack
        self._client_seq_num = seq + 1
        return msg[self.msg_slice].decode("ascii")


def parse_http_request(request: str) -> Optional[Tuple[str, str, str]]:
    request_lines = request.split(CRLF)
    if not request_lines:
        return None
    
    starting_line = request_lines[0]
    http_method = starting_line.split(CRLF)[0]
    json_body = request.find(CRLF * 2) + 4
    json_body = request[json_body:]
    return starting_line, http_method, json_body


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--addr", metavar="<server's address>", help="Server's address", type=str, default="127.0.0.1")
    parser.add_argument("--port", metavar="<server's port>", help="Server's port", type=int, default=12345)
    parser.add_argument("--logging", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    parser.add_argument("--username", metavar="<username>", help="Username", type=str, required=False)
    parser.add_argument("--password", metavar="<password>", help="Password", type=str, required=False)
    parser.add_argument("--signin", action="store_true", help="Sign in", required=False)
    parser.add_argument("--signup", action="store_true", help="Sign up", required=False)
    parser.add_argument("--filename", metavar="<filename>", help="Filename", type=str, required=False)
    parser.add_argument("--download", action="store_true", help="Download image", required=False)

    args = parser.parse_args()
    return args