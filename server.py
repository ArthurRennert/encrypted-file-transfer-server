"""
Encrypted File Transfer Server
server.py: contains Server class which has socket logics. Contains main loop of the server.
"""

__author__ = "Arthur Rennert"

import logging
import selectors
import uuid
import socket
import database
import protocol
import encryption
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
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
            protocol.RequestCode.REQUEST_REGISTRATION.value: self.handle_registration_request,
            protocol.RequestCode.REQUEST_SEND_PUBLIC_KEY.value: self.handle_encrypted_key_response,
            protocol.RequestCode.REQUEST_SEND_FILE.value: self.handle_send_file_request,
            protocol.RequestCode.REQUEST_CRC_VALID.value: self.handle_crc_valid_request,
            protocol.RequestCode.REQUEST_CRC_INVALID.value: self.handle_crc_invalid_request,
            protocol.RequestCode.REQUEST_CRC_INVALID_FOURTH_TIME.value: self.handle_crc_invalid_fourth_time_request
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
                    success = self.requestHandle[request_header.code](conn, data)
            if not success:  # return generic error upon failure.
                response_header = protocol.ResponseHeader(protocol.ResponseCode.RESPONSE_ERROR.value)
                self.write(conn, response_header.pack())
            self.database.set_last_seen(request_header.clientID, str(datetime.now()))
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
        response_fail = protocol.FailedRegistrationResponse()
        if not request.unpack(data):
            logging.error("Registration Request: Failed parsing request.")
            return self.write(conn, response_fail.pack())
        try:
            if not request.name != '' and all(ch.isalpha() or ch.isspace() for ch in request.name):
                logging.info(f"Registration Request: Invalid requested username ({request.name}))")
                return self.write(conn, response_fail.pack())
            if self.database.client_username_exists(request.name):
                logging.info(f"Registration Request: Username ({request.name}) already exists.")
                return self.write(conn, response_fail.pack())
        except:
            logging.error("Registration Request: Failed to connect to database.")
            return self.write(conn, response_fail.pack())
        client = database.Client(uuid.uuid4().hex, request.name, str(datetime.now()))
        if not self.database.store_client(client):
            logging.error(f"Registration Request: Failed to store client {request.name}.")
            return self.write(conn, response_fail.pack())

        logging.info(f"Successfully registered client {request.name}.")
        response = protocol.SuccessRegistrationResponse()
        response.clientID = client.ID
        response.header.payloadSize = protocol.CLIENT_ID_SIZE
        return self.write(conn, response.pack())

    def handle_encrypted_key_response(self, conn, data):
        """ Respond with aes key """
        request = protocol.PublicKeyRequest()
        response = protocol.EncryptedKeyResponse()

        if not request.unpack(data):
            logging.error("SendPublicKey Request: Failed to parse request header!")
        client_id = self.database.get_client_id(request.name)
        if not self.database.set_public_key(client_id, request.publicKey):
            logging.error(f"Registration Request: Failed to store client {request.name} public key.")
            return False
        aes_key = encryption.create_aes_key()
        # Store AES key in database
        if self.database.update_aes_key(client_id, aes_key) is False:
            print("Failed to update db with the new aes key")
        encrypted_aes = encryption.encrypt_aes_key_with_rsa_key(aes_key, request.publicKey)
        response.clientID = client_id
        response.encryptedKey = encrypted_aes
        response.header.payloadSize = protocol.CLIENT_ID_SIZE + len(encrypted_aes)
        logging.info(f"Encrypted Key response was successfully built to client {request.name}.")
        return self.write(conn, response.pack())

    def handle_send_file_request(self, conn, data):
        request = protocol.SendFileRequest()
        response = protocol.FileReceivedWithCRCResponse()

        if not request.unpack(data):
            logging.error("SendFile Request: Failed to parse request header!")

        decrypted_content = None
        try:
            # get client aes key
            aes_key = self.database.get_client_aes(request.header.clientID)

            # create aes cipher from the key
            cipher = AES.new(aes_key, AES.MODE_CBC, bytes(16))

            # decrypt content
            decrypted_content = cipher.decrypt(request.fileContent)
            decrypted_content = unpad(decrypted_content, 16)
        except:
            logging.error("Failed to create AES key");
            return False

        # store file in db
        file_name = request.fileName.partition(b'\0')[0].decode('utf-8')
        file_path = self.database.get_client_name(request.header.clientID).decode('utf-8') + '\\' + file_name
        new_file = database.File(request.header.clientID, file_name, file_path, False)
        self.database.insert_new_file(new_file)

        # calculate crc from the content
        crc = zlib.crc32(decrypted_content)

        response.clientID = request.header.clientID
        response.contentSize = request.contentSize
        response.fileName = request.fileName
        response.crc = crc
        response.header.payloadSize = protocol.CLIENT_ID_SIZE + protocol.CONTENT_SIZE + protocol.NAME_SIZE + protocol.CHECKSUM_SIZE
        logging.info(f"Successfully sent crc response to client {self.database.get_client_name(request.header.clientID).decode('utf-8')}.")
        return self.write(conn, response.pack())

    def handle_crc_valid_request(self, conn, data):
        request = protocol.CRCValidRequest()
        response = protocol.MessageReceivedResponse()

        if not request.unpack(data):
            logging.error("SendFile Request: Failed to parse request header!")

        file_name = request.fileName.partition(b'\0')[0].decode('utf-8')
        file_path = self.database.get_client_name(request.header.clientID).decode('utf-8') + '\\' + file_name
        self.database.update_file_verified(file_path, True)
        response.clientID = request.header.clientID
        response.header.payloadSize = protocol.CLIENT_ID_SIZE
        logging.info(f"Confirmation message send to client {self.database.get_client_name(request.header.clientID).decode('utf-8')}.")
        return self.write(conn, response.pack())

    def handle_crc_invalid_request(self, conn, data):
        request = protocol.CRCNotValidRequest()

        if not request.unpack(data):
            logging.error("SendFile Request: Failed to parse request header!")

        logging.info(
            f"CRC not valid with client {self.database.get_client_name(request.header.clientID).decode('utf-8')}.")
        return True

    def handle_crc_invalid_fourth_time_request(self, conn, data):
        request = protocol.CRCNotValidFourthTimeRequest()
        response = protocol.MsgRecvResponse()

        if not request.unpack(data):
            logging.error("SendFile Request: Failed to parse request header!")

        response.clientID = request.header.clientID
        response.header.payloadSize = protocol.CLIENT_ID_SIZE
        logging.info(
            f"CRC not valid with client {self.database.get_client_name(request.header.clientID).decode('utf-8')}. 3 times retried.")
        return self.write(conn, response.pack())
