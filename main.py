"""
Encrypted File Transfer Server
main.py: Entry point of Encrypted File Transfer Server.
"""
__author__ = "Arthur Rennert"

import utils
import server

if __name__ == '__main__':
    PORT_INFO = "port.info"
    port = utils.parsePort(PORT_INFO)
    server = server.Server('127.0.0.1', port)
    if not server.start():
        utils.stop_server(f"Server start exception: {server.lastErr}")

