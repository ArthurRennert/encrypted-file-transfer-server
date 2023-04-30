"""
Encrypted File Transfer Server
database.py: handles server's database.
"""

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
        """ Validate Client attributes """
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.Name or len(self.Name) >= protocol.NAME_SIZE:
            return False
        if not self.LastSeen:
            return False
        return True


class File:
    """ Represents a file entry """
    def __init__(self, client_id, file_name, path_name, verified):
        self.ID = client_id  # Client ID, 16 bytes.
        self.FileName = file_name  # File's name, 255 bytes.
        self.PathName = path_name  # File's relative path name, 255 bytes.
        self.Verified = verified  # A boolean value representing whether checksum verified with client.

    def validate(self):
        """ Validate Files attributes according to the requirements """
        if not self.ID or len(self.ID) != protocol.CLIENT_ID_SIZE:
            return False
        if not self.FileName or len(self.FileName) >= protocol.FILE_NAME_SIZE:
            return False
        if not self.PathName or len(self.PathName) >= protocol.PATH_NAME_SIZE:
            return False
        if self.Verified or not type(self.Verified) is bool:
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
              Verified BIT,
              FOREIGN KEY(ID) REFERENCES {Database.CLIENTS}(ID)
            );
            """)

    def client_username_exists(self, username):
        """ Check whether a username already exists in the database """
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

    def set_last_seen(self, client_id, time):
        """ Set client's last seen given a client id and the current time """
        return self.execute(f"UPDATE {Database.CLIENTS} SET LastSeen = ? WHERE ID = ?",
                            [time, client_id], True)

    def set_public_key(self, client_id, public_key):
        """ Set client's public key given a client id and a client public key """
        return self.execute(f"UPDATE {Database.CLIENTS} SET PublicKey = ? WHERE ID = ?",
                            [public_key, client_id], True)

    def get_client_id(self, name):
        """ Get client ID by given client name """
        return self.execute(f"SELECT ID FROM {Database.CLIENTS} WHERE Name = ?", [name])[0][0]

    def get_client_name(self, client_id):
        """ Get client name by given client ID """
        return self.execute(f"SELECT Name FROM {Database.CLIENTS} WHERE ID = ?", [client_id])[0][0]

    def get_client_public_key(self, client_id):
        """ Given a client id, return the client's public key """
        results = self.execute(f"SELECT PublicKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

    def get_client_aes(self, client_id):
        """ Get client's aes key by given client ID """
        results = self.execute(f"SELECT AESKey FROM {Database.CLIENTS} WHERE ID = ?", [client_id])
        if not results:
            return None
        return results[0][0]

    def get_is_file_verified(self, file_path):
        """ Get whether file verified given a PathName """
        results = self.execute(f"SELECT Verified FROM {Database.FILES} WHERE PathName = ?", [file_path])
        if not results:
            return None
        return results[0][0]

    def update_aes_key(self, client_id, key):
        """ Update client's aes key by given client ID and the aes key """
        if self.client_id_exists(client_id) is False:
            print(f"Client with id {client_id} doesn't exist")
            return False
        return self.execute(f"UPDATE {Database.CLIENTS} SET AESKey = ? WHERE ID = ?", [key, client_id], True)

    def insert_new_file(self, file):
        """ Insert new client's file to the database """
        if not type(file) is File or not file.validate():
            return False
        return self.execute(f"INSERT OR IGNORE INTO {Database.FILES} VALUES (?, ?, ?, ?)",
                            [file.ID, file.FileName, file.PathName, file.Verified], True)

    def update_file_verified(self, file_path, bool_val):
        """ Update whether file is verified (crc check with client succeeded) """
        return self.execute(f"UPDATE {Database.FILES} SET Verified = ? WHERE PathName = ?",
                            [bool_val, file_path], True)
