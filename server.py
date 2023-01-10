"""
Encrypted File Transfer Server
server.py: contains Server class which has socket logics. Contains main loop of the server.
"""

# TODO
# CHECK IF MASK PARAMETER NEEDED IN ACCEPT AND READ FUNCTIONS

__author__ = "Arthur Rennert"

import logging
import selectors
import uuid
import socket
import database
import protocol
from datetime import datetime


class Server:
    DATABASE = 'server.db'
    PACKET_SIZE = 1024  # Default packet size.
    MAX_QUEUED_CONN = 10  # Default maximum number of queued connections.
    IS_BLOCKING = False  # Blocking indicator!

    def __init__(self, host, port):
        """ Initialize server. Map request codes to handles. """
        logging.basicConfig(format='[%(levelname)s - %(asctime)s]: %(message)s', level=logging.INFO, datefmt='%H:%M:%S')
        self.host = host
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.database = database.Database(Server.DATABASE)
        self.lastErr = ""  # Last Error description.
        self.requestHandle = {
            protocol.ERequestCode.REQUEST_REGISTRATION.value: self.handle_registration_request,
            protocol.ERequestCode.REQUEST_SEND_PUBLIC_KEY.value: self.handle_public_key_request,
            protocol.ERequestCode.REQUEST_SEND_FILE.value: self.handleSendFileRequest,
            protocol.ERequestCode.REQUEST_CRC_VALID.value: self.handleCRCValidRequest,
            protocol.ERequestCode.REQUEST_CRC_INVALID.value: self.handleCRCInvalidRequest,
            protocol.ERequestCode.REQUEST_CRC_INVALID_FOURTH_TIME.value: self.handleCRCInvalidFourthTimeRequest
        }

    def accept(self, sock, mask):
        """ Accepts a connection from client """
        conn, address = sock.accept()
        conn.setblocking(Server.IS_BLOCKING)
        self.sel.register(conn, selectors.EVENT_READ, self.read)

    def read(self, conn, mask):
        """ Reads data from the client and parses it """
        logging.info("A client has connected.")
        data = conn.recv(Server.PACKET_SIZE)
        if data:
            request_header = protocol.RequestHeader()
            success = False
            if not request_header.unpack(data):
                logging.error("Failed to parse request header!")
            else:
                if request_header.code in self.requestHandle.keys():
                    success = self.requestHandle[request_header.code](conn, data)  # invoke corresponding handle.
            if not success:  # return generic error upon failure.
                response_header = protocol.ResponseHeader(protocol.EResponseCode.RESPONSE_ERROR.value)
                self.write(conn, response_header.pack())
            self.database.setLastSeen(request_header.clientID, str(datetime.now()))
        self.sel.unregister(conn)
        conn.close()

    def write(self, conn, data):
        """ Send a response to client"""
        size = len(data)
        sent = 0
        while sent < size:
            leftover = size - sent
            if leftover > Server.PACKET_SIZE:
                leftover = Server.PACKET_SIZE
            to_send = data[sent:sent + leftover]
            if len(to_send) < Server.PACKET_SIZE:
                to_send += bytearray(Server.PACKET_SIZE - len(to_send))
            try:
                conn.send(to_send)
                sent += len(to_send)
            except:
                logging.error("Failed to send response to " + conn)
                return False
        logging.info("Response sent successfully.")
        return True

    def start(self):
        """ Start listening for connections. Contains the main loop """
        self.database.initialize()
        try:
            sock = socket.socket()
            sock.bind((self.host, self.port))
            sock.listen(Server.MAX_QUEUED_CONN)
            sock.setblocking(Server.IS_BLOCKING)
            self.sel.register(sock, selectors.EVENT_READ, self.accept)
        except Exception as e:
            self.lastErr = e
            return False
        print(f"Server is listening for connections on port {self.port}..")
        while True:
            try:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
            except Exception as e:
                logging.exception(f"Server main loop exception: {e}")

    def handle_registration_request(self, conn, data):
        """ Register a new user. Save to db. """
        request = protocol.RegistrationRequest()
        response = protocol.RegistrationResponse()
        if not request.unpack(data):
            logging.error("Registration Request: Failed parsing request.")
            return False
        try:
            if not request.name.isalnum():
                logging.info(f"Registration Request: Invalid requested username ({request.name}))")
                return False
            if self.database.client_username_exists(request.name):
                logging.info(f"Registration Request: Username ({request.name}) already exists.")
                return False
        except:
            logging.error("Registration Request: Failed to connect to database.")
            return False

        client = database.Client(uuid.uuid4().hex, request.name, str(datetime.now()))
        if not self.database.store_client(client):
            logging.error(f"Registration Request: Failed to store client {request.name}.")
            return False
        logging.info(f"Successfully registered client {request.name}.")
        response.clientID = client.ID
        response.header.payloadSize = protocol.CLIENT_ID_SIZE
        return self.write(conn, response.pack())

    # need to modify this function. need to store public key of client. not to send public key to client
    def handle_public_key_request(self, conn, data):
        """ Respond with public key of requested user id """
        request = protocol.PublicKeyRequest()
        response = protocol.PublicKeyResponse()
        if not request.unpack(data):
            logging.error("PublicKey Request: Failed to parse request header!")
        key = self.database.get_client_public_key(request.clientID)
        if not key:
            logging.info(f"PublicKey Request: clientID doesn't exists.")
            return False
        response.clientID = request.clientID
        response.publicKey = key
        response.header.payloadSize = protocol.CLIENT_ID_SIZE + protocol.PUBLIC_KEY_SIZE
        logging.info(f"Public Key response was successfully built to clientID ({request.header.clientID}).")
        return self.write(conn, response.pack())
