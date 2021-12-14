import socket
import select
from config import *

IP = "127.0.0.1"
PORT = 1234

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# SO_ - socket option
# SOL_ - socket option level
# Sets REUSEADDR (as a socket option) to 1 on socket
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Bind, so server informs operating system that it's going to use given IP and port
# For a server using 0.0.0.0 means to listen on all available interfaces, useful to connect locally to 127.0.0.1 and remotely to LAN interface IP
server_socket.bind((IP, PORT))

# This makes server listen to new connections
server_socket.listen()

# List of sockets for select.select()
sockets_list = [server_socket]

# List of connected clients - socket as a key, user header and name as data
clients = {}

# Aurelio of all online users
online_users = {}

print(f'Listening for connections on {IP}:{PORT}...')

# Handles message receiving
def receive_message(client_socket):
    try:
        message_opcode = int(client_socket.recv(MSG_OPCODE).decode('utf-8').strip())
        print("message_opcode: {}".format(message_opcode))

        message_from = client_socket.recv(USER_LENGTH).decode('utf-8')
        print("message_from: {}".format(message_from))

        if(message_opcode == 1):
            message_to = client_socket.recv(USER_LENGTH)
            message_to = "ALL"
            data = client_socket.recv(DATA_LENGTH)

        elif(message_opcode == 2):
            message_to = client_socket.recv(USER_LENGTH)
            message_to = str(message_to.decode('utf-8').strip())
            data = client_socket.recv(DATA_LENGTH)

        elif(message_opcode == 3):
            message_to = client_socket.recv(USER_LENGTH)
            message_to = str(message_to.decode('utf-8').strip())
            tresh_data = client_socket.recv(DATA_LENGTH)

            data = "         Online Users\n"
            for i in online_users:
                data = data + ("\n{} - {}").format(i, online_users[i])
            data = bytes(data, 'utf-8')

        elif(message_opcode == 4):
            message_to = client_socket.recv(USER_LENGTH)
            message_to = str(message_to.decode('utf-8').strip())
            tresh_data = client_socket.recv(DATA_LENGTH)
            data = """

                     Help Guide

            1 - Broadcast communication
            2 - Direct communication
            3 - List all online users
            4 - Help

            """
            data = bytes(data, 'utf-8')

        else:
            pass

        print("message_to: {}".format(message_to))
        print(data.decode('utf-8').strip())

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not data:
            return False

        return {'header': DATA_LENGTH, 'opcode': message_opcode, "from": message_from, 'to': message_to, 'data': data}

    except Exception as e:
        print(str(e))
        if(str(e) == "invalid literal for int() with base 10: ''"):
            return True
        return False

def new_user(client_socket):
    try:
        # Receive our "header" containing message length, it's size is defined and constant
        message_header = client_socket.recv(DATA_LENGTH)

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not len(message_header):
            return False

        # Convert header to int value
        message_length = int(message_header.decode('utf-8').strip())
        data = client_socket.recv(message_length+1)

        online_users[str(len(online_users) + 1)] = data.decode('utf-8').strip()

        print("A new user has been additioned online users.\n{}\n".format(online_users))

        return {'header': message_header, 'data': data}

    except Exception as e:
        print(str(e))
        return False

while True:
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            client_socket, client_address = server_socket.accept()

            user = new_user(client_socket)

            if user is False:
                continue

            sockets_list.append(client_socket)

            clients[client_socket] = user

            print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))

        else:
            message = receive_message(notified_socket)

            if message is False:
                print('Closed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))

                sockets_list.remove(notified_socket)

                del clients[notified_socket]
                continue
        
            if message is True:
                continue

            user = clients[notified_socket]

            print(f'Received message from {user["data"].decode("utf-8")} to {message["to"]}: {message["data"].decode("utf-8")}')

            for client_socket in clients:
                # size of user sender
                message_opcode = f"{(message['opcode']):<{MSG_OPCODE}}".encode('utf-8')
                # size of user sender
                message_from = f"{(message['from']):<{USER_LENGTH}}".encode('utf-8')
                # size of user sender
                message_to = f"{(message['to']):<{USER_LENGTH}}".encode('utf-8')

                if client_socket != notified_socket:   
                    if message["to"] == "ALL":
                        client_socket.send(message_opcode + message_from + message_to + message['data'])

                    elif clients[client_socket]['data'].decode('utf-8') == message["to"]:
                        client_socket.send(message_opcode + message_from + message_to + message['data'])

                elif int(message['opcode']) == 3 and len(online_users) > 1:
                    data = f"{(message['data']).decode('utf-8'):<{DATA_LENGTH}}".encode('utf-8')
                    client_socket.send(message_opcode + message_from + message_to + message['data'])

                elif int(message['opcode']) == 4 and len(online_users) > 1:
                    data = f"{(message['data']).decode('utf-8'):<{DATA_LENGTH}}".encode('utf-8')
                    client_socket.send(message_opcode + message_from + message_to + message['data'])

    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)
        del clients[notified_socket]