# first of all import the socket library
import socket
import os


def main():
    s = socket.socket()  # create a socket
    print("Socket successfully created")

    port_file_path = './port.info'
    if os.path.exists(port_file_path):
        with open(port_file_path) as file:  # get port from file
            first_line = file.readlines()[0]
            port = int(first_line)
    else:
        port = 1234  # default port

    # s.bind((socket.gethostname(), port))  # bind to the port
    s.bind(('127.0.0.1', port))  # bind to the port
    print("socket bounded to", port)

    s.listen(5)  # put the socket into listening mode
    print("socket is listening")
    count = 0
    # a forever loop until we interrupt it or an error occurs
    while True:
        conn, addr = s.accept()  # establish connection with client.
        count += 1
        print('count=', count)
        print('got connection from', addr)

        # send a thank-you message to the client. encoding to send byte type.
        msg_to_c = 'Thank you for connecting'
        print('msg TO client:', msg_to_c)
        conn.send(msg_to_c.encode())

        # receive data stream. it won't accept data packet greater than 1024 bytes
        msg_from_client = conn.recv(1024).decode()
        if not msg_from_client:
            # if data is not received break
            break
        print("msg FROM client:" + str(msg_from_client))

        # send a thank-you message to the client. encoding to send byte type.
        msg_to_c = 'goodbye'
        print('msg TO client:', msg_to_c)
        conn.send(msg_to_c.encode())

        conn.close()  # Close the connection with the client
        # break  # uncomment this to debug - kills the server after 1 client
    return


if __name__ == '__main__':
    main()
