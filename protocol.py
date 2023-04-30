"""
Encrypted File Transfer Server
protocol.py: defines protocol structs and constants.
"""

__author__ = "Arthur Rennert"

import struct
from enum import Enum

SERVER_VERSION = 3
DEFAULT_VALUE = 0     # Default value to initialize inner fields.
HEADER_SIZE = 7       # Header size without clientID. (version, code, payload size).
CLIENT_ID_SIZE = 16
CONTENT_SIZE = 4
NAME_SIZE = 255
FILE_NAME_SIZE = 255
PATH_NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
ENCRYPTED_AES_KEY_SIZE = 128
AES_KEY_SIZE = 16
CHECKSUM_SIZE = 4


# Request Codes
class RequestCode(Enum):
    REQUEST_REGISTRATION = 1100  # uuid ignored.
    REQUEST_SEND_PUBLIC_KEY = 1101
    REQUEST_SEND_FILE = 1103
    REQUEST_CRC_VALID = 1104
    REQUEST_CRC_INVALID = 1005  # request 1103 coming right after this request
    REQUEST_CRC_INVALID_FOURTH_TIME = 1106


# Responses Codes
class ResponseCode(Enum):
    RESPONSE_REGISTRATION_SUCCESS = 2100
    RESPONSE_REGISTRATION_FAILED = 2101
    RESPONSE_ENCRYPTED_KEY = 2102
    RESPONSE_SUCCESS_FILE_WITH_CRC = 2103
    RESPONSE_MSG_RECEIVED_THANKS = 2104
    RESPONSE_ERROR = 9999


class RequestHeader:
    def __init__(self):
        self.clientID = b""
        self.version = DEFAULT_VALUE      # 1 byte
        self.code = DEFAULT_VALUE         # 2 bytes
        self.payloadSize = DEFAULT_VALUE  # 4 bytes
        self.SIZE = CLIENT_ID_SIZE + HEADER_SIZE

    def unpack(self, data):
        """ Little Endian unpack Request Header """
        try:
            self.clientID = struct.unpack(f"<{CLIENT_ID_SIZE}s", data[:CLIENT_ID_SIZE])[0]
            header_data = data[CLIENT_ID_SIZE:CLIENT_ID_SIZE + HEADER_SIZE]
            self.version, self.code, self.payloadSize = struct.unpack("<BHL", header_data)
            return True
        except:
            self.__init__()  # reset values
            return False


class ResponseHeader:
    def __init__(self, code):
        self.version = SERVER_VERSION     # 1 byte
        self.code = code                  # 2 bytes
        self.payloadSize = DEFAULT_VALUE  # 4 bytes
        self.SIZE = HEADER_SIZE

    def pack(self):
        """ Little Endian pack Response Header """
        try:
            return struct.pack("<BHL", self.version, self.code, self.payloadSize)
        except:
            return b""


class RegistrationRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header and Name """
        if not self.header.unpack(data):
            return False
        try:
            # trim the byte array after the null terminating character.
            name_data = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = struct.unpack(f"<{NAME_SIZE}s", name_data)[0].partition(b'\0')[0].decode('utf-8')
            return True
        except:
            self.name = b""
            return False


class SuccessRegistrationResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_REGISTRATION_SUCCESS.value)
        self.clientID = b""

    def pack(self):
        """ Little Endian pack Response Header and clientID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""


class FailedRegistrationResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_REGISTRATION_FAILED.value)

    def pack(self):
        """ Little Endian pack Response Header """
        try:
            data = self.header.pack()
            return data
        except:
            return b""


class PublicKeyRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.name = b""
        self.publicKey = b""

    def unpack(self, data):
        """ Little Endian unpack Request Header, Name, and Public Key """
        if not self.header.unpack(data):
            return False
        try:
            name_data = data[self.header.SIZE:self.header.SIZE + NAME_SIZE]
            self.name = struct.unpack(f"<{NAME_SIZE}s", name_data)[0].partition(b'\0')[0].decode('utf-8')
            key_data = data[self.header.SIZE + NAME_SIZE:self.header.SIZE + NAME_SIZE + PUBLIC_KEY_SIZE]
            self.publicKey = struct.unpack(f"<{PUBLIC_KEY_SIZE}s", key_data)[0]
            return True
        except:
            self.name = b""
            self.publicKey = b""
            return False


class EncryptedKeyResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_ENCRYPTED_KEY.value)
        self.clientID = b""
        self.encryptedKey = b""

    def pack(self):
        """ Little Endian pack Response Header, ClientID, and Encrypted Key """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<{ENCRYPTED_AES_KEY_SIZE}s", self.encryptedKey)
            return data
        except:
            return b""


class SendFileRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.contentSize = DEFAULT_VALUE  # 4 bytes
        self.fileName = b''
        self.fileContent = b''

    def unpack(self, data):
        """ Little Endian unpack Request Header, Content Size, File Name, and File Content """
        if not self.header.unpack(data):
            return False
        try:
            content_size = data[self.header.SIZE:self.header.SIZE + CONTENT_SIZE]
            self.contentSize = struct.unpack("<L", content_size)[0]
            offset = self.header.SIZE + CONTENT_SIZE
            file_name = data[offset:offset + FILE_NAME_SIZE]
            self.fileName = struct.unpack(f"<{FILE_NAME_SIZE}s", file_name)[0]
            offset = offset + FILE_NAME_SIZE
            file_content = data[offset:offset+self.contentSize]
            self.fileContent = struct.unpack(f"<{self.contentSize}s", file_content)[0]
            return True
        except:
            self.contentSize = DEFAULT_VALUE
            self.fileName = b''
            self.fileContent = b''
            return False


class FileReceivedWithCRCResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_SUCCESS_FILE_WITH_CRC.value)
        self.clientID = b""
        self.contentSize = DEFAULT_VALUE  # 4 bytes
        self.fileName = b''
        self.crc = DEFAULT_VALUE

    def pack(self):
        """ Little Endian pack Response Header, ClientID, Content Size, File Name, and Checksum """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            data += struct.pack(f"<L", self.contentSize)
            data += struct.pack(f"<{FILE_NAME_SIZE}s", self.fileName)
            data += struct.pack(f"<L", self.crc)
            return data
        except:
            return b""


class CRCValidRequest:
    def __init__(self):
        self.header = RequestHeader()
        self.fileName = b''

    def unpack(self, data):
        """ Little Endian unpack Request Header and File Name """
        if not self.header.unpack(data):
            return False
        try:
            file_name = data[self.header.SIZE:self.header.SIZE + FILE_NAME_SIZE]
            self.fileName = struct.unpack(f"<{FILE_NAME_SIZE}s", file_name)[0]
            return True
        except:
            self.fileName = b''
            return False


class MessageReceivedResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_MSG_RECEIVED_THANKS.value)
        self.clientID = b""

    def pack(self):
        """ Little Endian pack Response Header, ClientID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""


class CRCNotValidRequest:
    def __init__(self):
        self.header = RequestHeader()

    def unpack(self, data):
        """ Little Endian unpack Request Header """
        if not self.header.unpack(data):
            return False
        return True


class CRCNotValidFourthTimeRequest:
    def __init__(self):
        self.header = RequestHeader()

    def unpack(self, data):
        """ Little Endian unpack Request Header """
        if not self.header.unpack(data):
            return False
        return True


class MsgRecvResponse:
    def __init__(self):
        self.header = ResponseHeader(ResponseCode.RESPONSE_MSG_RECEIVED_THANKS.value)
        self.clientID = b""

    def pack(self):
        """ Little Endian pack Response Header, ClientID """
        try:
            data = self.header.pack()
            data += struct.pack(f"<{CLIENT_ID_SIZE}s", self.clientID)
            return data
        except:
            return b""