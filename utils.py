"""
Encrypted File Transfer Server
utils.py: collection of small functions which make Encrypted File Transfer server's patterns shorter and easier.
"""
__author__ = "Arthur Rennert"


def stop_server(err):
    """ Print err and stop script execution """
    print(f"\nFatal Error: {err}\nEncrypted File Transfer Server will halt!")
    exit(1)


def parse_port(filepath):
    """
    Parse filepath for port number. Return port as integer.
    Note: Only the first line will be read. On any failure, the default port (1234) will be returned.
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
