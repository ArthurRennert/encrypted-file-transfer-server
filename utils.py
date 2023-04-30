"""
Encrypted File Transfer Server
utils.py: parsing and stop server functions for Encrypted File Transfer server usage.
"""

__author__ = "Arthur Rennert"


def stop_server(err):
    """ Print err and stop script execution """
    print(f"\nFatal Error: {err}\nEncrypted File Transfer Server will halt!")
    exit(1)


def parse_port(filepath):
    """
    Parse (only the first line) filepath for port number. Return port as integer.
    In case of failure, the default port (1234) will be returned.
    """
    port = None
    try:
        with open(filepath, "r") as port_info:
            port = port_info.readline().strip()
            port = int(port)
    except (ValueError, FileNotFoundError):
        port = 1234
    finally:
        return port
