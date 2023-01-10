"""
Encrypted File Transfer Server
database.py: handles server's database.
"""

# TODO
# CHECK IF ADD ID TO CONSTRUCTOR PARAMETERS LIST
# CHECK IF REMOVE FILE IS NEEDED


__author__ = "Arthur Rennert"

import logging
import sqlite3
import protocol

DEFAULT_VALUE = 0


class Client:
    """ Represents a client entry """

    def __init__(self, cid, cname, last_seen):
        self.ID = bytes.fromhex(cid)  # Unique client ID, 16 bytes.
        self.Name = cname  # Client's name, null terminated ascii string, 255 bytes.
        self.PublicKey = DEFAULT_VALUE  # Client's public key, 160 bytes.
        self.LastSeen = last_seen  # The Date & time of client's last request.
        self.AESKey = DEFAULT_VALUE

    def validate(self):
        """ Validate Client attributes according to the requirements """
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.Name or len(self.Name) >= protocol.NAME_SIZE:
            return False
        # if not self.PublicKey or len(self.PublicKey) != protocol.PUBLIC_KEY_SIZE:
        #     return False
        if not self.LastSeen:
            return False
        # if not self.AESKey or len(self.AESKey) != protocol.AES_KEY_SIZE:
        #     return False
        return True


class File:
    """ Represents a file entry """

    def __init__(self, client_id, file_name, path_name, verified, content):
        self.ID = client_id  # Client ID, 16 bytes.
        self.FileName = file_name  # File's name, 255 bytes.
        self.PathName = path_name  # File's relative path name, 255 bytes.
        self.Verified = verified  # A boolean value representing whether checksum verified with client.

    def validate(self):
        """ Validate Files attributes according to the requirements """
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.FileName or len(self.FileName) != protocol.FILE_NAME_SIZE:
            return False
        if not self.PathName or len(self.PathName) != protocol.PATH_NAME_SIZE:
            return False
        if not self.Verified:
            return False
        return True


class Database:
    CLIENTS = 'clients'
    FILES = 'files'

    def __init__(self, name):
        self.name = name

    def connect(self):
        conn = sqlite3.connect(self.name)  # doesn't raise exception.
        conn.text_factory = bytes
        return conn

    def executescript(self, script):
        conn = self.connect()
        try:
            conn.executescript(script)
            conn.commit()
        except:
            pass  # table might exist already
        conn.close()

    def execute(self, query, args, commit=False, get_last_row=False):
        """ Given a query and args, execute query, and return the results """
        results = None
        conn = self.connect()
        try:
            cur = conn.cursor()
            cur.execute(query, args)
            if commit:
                conn.commit()
                results = True
            else:
                results = cur.fetchall()
            if get_last_row:
                results = cur.lastrowid  # special query.
        except Exception as e:
            logging.exception(f'database execute: {e}')
        conn.close()  # commit is not required.
        return results

    def initialize(self):
        # Try to create Clients table
        self.executescript(f"""
            CREATE TABLE {Database.CLIENTS}(
              ID CHAR(16) NOT NULL PRIMARY KEY,
              Name CHAR(255) NOT NULL,
              PublicKey CHAR(160) NOT NULL,
              LastSeen DATE,
              AESKey CHAR(16) NOT NULL
            );
            """)

        # Try to create Files table
        self.executescript(f"""
            CREATE TABLE {Database.FILES}(
              ID CHAR(16) NOT NULL PRIMARY KEY,
              FileName CHAR(255) NOT NULL,
              PathName CHAR(255) NOT NULL,
              Verified INTEGER,
              FOREIGN KEY(ID) REFERENCES {Database.CLIENTS}(ID)
            );
            """)

    def client_username_exists(self, username):
        """ Check whether a username already exists within the database """
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE Name = ?", [username])
        if not results:
            return False
        return len(results) > 0

    def client_id_exists(self, client_id):
        """ Check whether a client ID already exists within the database """
        results = self.execute(f"SELECT * FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return False
        return len(results) > 0

    def store_client(self, client):
        """ Stores a client into the database """
        if not type(client) is Client or not client.validate():
            return False
        return self.execute(f"INSERT INTO {Database.CLIENTS} VALUES (?, ?, ?, ?, ?)",
                            [client.ID, client.Name, client.PublicKey, client.LastSeen, client.AESKey], True)

    def store_file(self, file):
        """ Store a message into database """
        if not type(file) is File or not file.validate():
            return False
        results = self.execute(
            f"INSERT INTO {Database.FILES} VALUES (?, ?, ?, ?)",
            [file.ID, file.FileName, file.PathName, file.Verified], True)
        return results

    def remove_file(self, client_id):
        """ Removes a file by client id from the database """
        return self.execute(f"DELETE FROM {Database.FILES} WHERE ID = ?", [client_id], True)

    def set_last_seen(self, client_id, time):
        """ Set last seen given a client id """
        return self.execute(f"UPDATE {Database.CLIENTS} SET LastSeen = ? WHERE ID = ?",
                            [time, client_id], True)

    def get_client_public_key(self, client_id):
        """ Given a client id, return the client's public key """
        results = self.execute(f"SELECT PublicKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]
