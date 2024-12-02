

# Standard modules
import hashlib
import json
import logging
import os
import random
import requests
import socket
import time

# User-defined modules
from constants import *
from utils import Context, parse_http_request


class UDPClient:
    def __init__(self, addr: str, port: int):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._context = self._handshake(addr=addr, port=port)
        os.makedirs("downloads", exist_ok=True)

    def _handshake(self, addr: int, port: int, byteorder: str = "big"):
        client_isn = random.randint(1, 1000000000)
        msg = b''
        msg += FLAG_SYN.to_bytes(1, byteorder=byteorder)
        msg += client_isn.to_bytes(4, byteorder=byteorder)
        msg += (0).to_bytes(4, byteorder=byteorder)  # Initial ACK is 0
        logging.info(f"[→] Sending SYN: flag={FLAG_SYN}, seq={client_isn}, ack=0")
        self._socket.sendto(msg, (addr, port))
        
        # Receive SYN-ACK
        response, _ = self._socket.recvfrom(BUFFER_SIZE)
        received_flag = response[0]
        server_isn = int.from_bytes(response[1:5], byteorder=byteorder)
        ack = int.from_bytes(response[5:9], byteorder=byteorder)
        logging.info(f"[←] Received SYN-ACK: flag={received_flag}, seq={server_isn}, ack={ack}")
        if received_flag != FLAG_SYN_ACK or ack != client_isn + 1:
            logging.error("Invalid SYN-ACK received")
            return FAILURE
            
        # Send ACK
        final_ack = b''
        final_ack += FLAG_ACK.to_bytes(1, byteorder=byteorder)
        final_ack += (client_isn + 1).to_bytes(4, byteorder=byteorder)
        final_ack += (server_isn + 1).to_bytes(4, byteorder=byteorder)
        logging.info(f"[→] Sending ACK: flag={FLAG_ACK}, seq={client_isn + 1}, ack={server_isn + 1}")
        self._socket.sendto(final_ack, (addr, port))

        server_addr = addr
        server_port = port
        client_addr = self._socket.getsockname()[0]
        client_port = self._socket.getsockname()[1]
        context = Context(server_addr, server_port, client_addr, client_port, server_isn, client_isn)
        logging.info(f"[*] Handshake done.")
        return context

    def signup(self, username: str, password: str):
        context = self._context
        json_body = {"username": username, "password": password}
        json_body = json.dumps(json_body)

        http_method = f"POST /signup/{username}"
        request = f"{http_method}{CRLF}Content-Length:{len(json_body)}{CRLF * 2}"
        request += json_body
        request = context.encapsulate(request)
        logging.info(f"[→] REQUEST: [{http_method}] | DATA: {json_body}")
        self._socket.sendto(request, (context.server_addr, context.server_port))

        # Wait for response
        response, _ = self._socket.recvfrom(BUFFER_SIZE)
        response = context.decapsulate(response)
        logging.info(f"[←] RESPONSE: {response}")
        response = json.loads(response)
        if not response["status"] == 200:
            return FAILURE, None, None
        return SUCCESS, username, password

    def signin(self, username: str, password: str):
        context = self._context

        http_method = "POST /signin"
        json_body = {"username": username, "password": password}
        json_body = json.dumps(json_body)
        request = f"{http_method}{CRLF}Content-Length:{len(json_body)}{CRLF * 2}"
        request += json_body
        request = context.encapsulate(request)
        logging.info(f"[→] REQUEST: [{http_method}] | DATA: {json_body}")
        self._socket.sendto(request, (context.server_addr, context.server_port))

        # Wait for response
        response, _ = self._socket.recvfrom(BUFFER_SIZE)
        response = context.decapsulate(response)
        logging.info(f"[←] RESPONSE: {response}")
        response = json.loads(response)
        if not response["status"] == 200:
            return FAILURE
        return SUCCESS

    def request_content(self, filename: str):
        context = self._context

        http_method = f"GET /content/{filename}"
        json_body = {"filename": filename}
        json_body = json.dumps(json_body)
        request = f"{http_method}{CRLF}Content-Length:{len(json_body)}{CRLF * 2}"
        request += json_body
        request = context.encapsulate(request)
        logging.info(f"[→] REQUEST [{http_method}] | DATA: {json_body}")
        self._socket.sendto(request, (context.server_addr, context.server_port))

        save_path = os.path.join("downloads", filename)
        logging.info(f"[←] Downloading {filename} to {save_path}...")
        with open(save_path, "wb") as f:
            # Get content size first
            size_packet, _ = self._socket.recvfrom(BUFFER_SIZE)
            total_size = int.from_bytes(size_packet[9:], byteorder="big")
            received_size = 0

            # Receive data until we get the complete file
            while received_size < total_size:
                chunk, _ = self._socket.recvfrom(BUFFER_SIZE)
                data = chunk[9:]  # Skip header bytes
                f.write(data)
                received_size += len(data)

        # Wait for response
        response, _ = self._socket.recvfrom(BUFFER_SIZE)
        response = context.decapsulate(response)
        logging.info(f"[←] Received response: {response}")
        response = json.loads(response)
        if not response["status"] == 200:
            return FAILURE  
        return SUCCESS


class UDPServer:
    isn_slice = slice(1, 5)
    ack_slice = slice(5, 9)

    def __init__(
        self,
        addr: str,
        port: int,
        buff_size: int = BUFFER_SIZE,
    ):
        self._addr = addr
        self._port = port
        self._buff_size = buff_size

        self._contexts = {}
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if not os.path.exists(".auth.json"):
            with open(".auth.json", "w") as f:
                json.dump({}, f)

        with open(".auth.json", "r") as f:
            self._auth_dict = json.load(f)

        os.makedirs(".content", exist_ok=True)
        if not os.path.exists(".content/lenna.png"):
            url = "https://upload.wikimedia.org/wikipedia/en/thumb/7/7d/Lenna_%28test_image%29.png/440px-Lenna_%28test_image%29.png"
            response = requests.get(url)
            with open(".content/lenna.png", "wb") as f:
                f.write(response.content)
    
    def run(self):
        self._socket.bind((self._addr, self._port))
        logging.info(f"[*] Server is Listening on {self._addr}:{self._port}")

        while True:
            msg, connection = self._socket.recvfrom(BUFFER_SIZE)
            server_addr = self._socket.getsockname()[0]
            server_port = self._socket.getsockname()[1]
            client_addr = connection[0]
            client_port = connection[1]
            logging.info(f"[*] Server accept the connection from {client_addr}:{client_port}")

            context_id = f"{server_addr}:{server_port}-{client_addr}:{client_port}"
            if context_id not in self._contexts:
                context = self._handshake(msg, connection)
                self._contexts[context_id] = context
            else:
                context = self._contexts[context_id]
                _ = self._handle_request(msg, connection, context)

    def _handshake(self, msg, connection, byteorder="big"):
        # Process SYN
        received_flag = msg[0]
        client_isn = int.from_bytes(msg[self.isn_slice], byteorder=byteorder)
        server_isn = random.randint(1, 1000000000)
        ack = int.from_bytes(msg[self.ack_slice], byteorder=byteorder)

        client_addr = connection[0]
        client_port = connection[1]
        server_addr = self._socket.getsockname()[0]
        server_port = self._socket.getsockname()[1]
        logging.info(
            f"[←] Received SYN from {client_addr}:{client_port}: "
            f"flag={received_flag}, seq={client_isn}, ack={ack}"
        )
        if received_flag != FLAG_SYN:  # Must be SYN
            logging.error("Invalid SYN received")
            return None
            
        # Generate SYN-ACK
        response = b''
        response += FLAG_SYN_ACK.to_bytes(1, byteorder=byteorder)
        response += server_isn.to_bytes(4, byteorder=byteorder)
        response += (client_isn + 1).to_bytes(4, byteorder=byteorder)
        
        logging.info(
            f"[→] Sending SYN-ACK to {client_addr}:{client_port}: "
            f"flag={FLAG_SYN_ACK}, seq={server_isn}, ack={client_isn + 1}"
        )
        self._socket.sendto(response, connection)
        context = Context(server_addr, server_port, client_addr, client_port, server_isn, client_isn)
        
        # Wait for final ACK
        msg, _ = self._socket.recvfrom(BUFFER_SIZE)
        received_flag = msg[0]
        if received_flag != FLAG_ACK:  # Must be ACK
            logging.error("Invalid ACK received")
            return None
        logging.info(f"[←] Received final ACK from {client_addr}:{client_port}")
        return context

    def _handle_request(self, msg, connection, context):
        request = context.decapsulate(msg)
        client_addr = connection[0]
        client_port = connection[1]

        http_elements = parse_http_request(request)
        if http_elements is None:
            logging.error(f"[←] Invalid HTTP request from {client_addr}:{client_port}")
            return FAILURE
        starting_line, http_method, json_body = http_elements
        json_body = json.loads(json_body)
        logging.info(f"[←] REQUEST [{http_method}] from {client_addr}:{client_port}")

        if starting_line.startswith('POST /signup'):
            # User creation request
            username = json_body.get('username')
            password = json_body.get('password')
            password_hashed = hashlib.sha256(password.encode()).hexdigest()
            message = f"User {username} created successfully"
            if username in self._auth_dict:
                message = f"User {username} already exists"
                logging.error(message)
            else:
                self._auth_dict[username] = password_hashed
                with open(".auth.json", "w") as f:
                    json.dump(self._auth_dict, f)
            logging.info(message)
                
            response = {
                "status": 200 if message == f"User {username} created successfully" else 401,
                "content-type": "application/json",
                "message": message,
                "timestamp": time.time(),
            }
            response = json.dumps(response)
            response = context.encapsulate(response)
            self._socket.sendto(response, connection)
            return SUCCESS
            
        # Sign in request
        elif starting_line.startswith('POST /signin'):
            # In a real application, verify credentials here
            username = json_body.get('username')
            password = json_body.get('password')
            password_hashed = hashlib.sha256(password.encode()).hexdigest()

            message = f"User {username} signed in successfully"
            if self._auth_dict.get(username):
                if self._auth_dict[username] == password_hashed:
                    logging.info(message)
                else:
                    message = f"Invalid password for user {username}"
                    logging.error(message)
            else:
                message = f"User {username} not found"
                logging.error(message)
            response = {
                "status": 200 if message == f"User {username} signed in successfully" else 401,
                "content-type": "application/json",
                "message": message,
                "timestamp": time.time(),
            }
            # Send response
            response = json.dumps(response)
            response = context.encapsulate(response)
            self._socket.sendto(response, connection)
            return SUCCESS
            
        # Content request
        elif starting_line.startswith('GET /content'):
            # In a real application, return some content here
            filename = json_body.get('filename')
            message = f"File {filename} is downloaded successfully"
            if filename not in os.listdir(".content"):
                message = f"File {filename} not found"
                logging.error(message)

            # Read file content
            with open(f".content/{filename}", "rb") as f:
                content = f.read()
        
            # Send file size first
            size_packet = b''
            size_packet += FLAG_REQUEST.to_bytes(1, byteorder="big")
            size_packet += context.server_seq_num.to_bytes(4, byteorder="big")
            size_packet += context.client_seq_num.to_bytes(4, byteorder="big")
            size_packet += len(content).to_bytes(4, byteorder="big")
            self._socket.sendto(size_packet, connection)

            # Send file in chunks
            chunk_size = 1024
            for i in range(0, len(content), chunk_size):
                chunk = content[i:i + chunk_size]
                packet = b''
                packet += FLAG_REQUEST.to_bytes(1, byteorder="big")
                packet += context.server_seq_num.to_bytes(4, byteorder="big")
                packet += context.client_seq_num.to_bytes(4, byteorder="big")
                packet += chunk
                self._socket.sendto(packet, connection)
                time.sleep(0.001)  # Small delay to prevent network congestion

            response = {
                "status": 200 if message == f"File {filename} is downloaded successfully" else 404,
                "content-type": "application/json",
                "message": message,
                "timestamp": time.time(),
            }
            response = json.dumps(response)
            response = context.encapsulate(response)
            self._socket.sendto(response, connection)
            logging.info(f"[→] Sent content to {client_addr}:{client_port}")
            return SUCCESS
            
        # Unknown request
        else:
            response = {
                "status": 400,
                "content-type": "application/json",
                "message": "Unknown request type"
            }
            response = json.dumps(response)
            response = context.encapsulate(response)
            self._socket.sendto(response, connection)
            return FAILURE
