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
        # Receive our "header" containing message length, it's size is defined and constant
        message_opcode = int(client_socket.recv(MSG_OPCODE).decode('utf-8'))
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
            message_to = message_from
            print(online_users)
            data = "\n"
            for i in online_users:
                data = data + ("{} - {}\n").format(i, online_users[i])
            data = bytes(data, 'utf-8')

        elif(message_opcode == 4):
            message_to = message_from.strip()
            print(online_users)
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
        print(data)

        # If we received no data, client gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
        if not data:
            return False

        # Convert header to int value
        # message_length = int(data.decode('utf-8').strip())

        # Return an object of message header and message data
        return {'header': DATA_LENGTH, 'opcode': message_opcode, "from": message_from, 'to': message_to, 'data': data}

    except Exception as e:
        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        print(str(e))
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

        # Return an object of message header and message data

        online_users[str(len(online_users) + 1)] = data.decode('utf-8').strip()

        print("Att all online users.\n{}\n".format(online_users))

        return {'header': message_header, 'data': data}

    except:
        # If we are here, client closed connection violently, for example by pressing ctrl+c on his script
        # or just lost his connection
        # socket.close() also invokes socket.shutdown(socket.SHUT_RDWR) what sends information about closing the socket (shutdown read/write)
        # and that's also a cause when we receive an empty message
        return False

while True:
    # Calls Unix select() system call or Windows select() WinSock call with three parameters:
    #   - rlist - sockets to be monitored for incoming data
    #   - wlist - sockets for data to be send to (checks if for example buffers are not full and socket is ready to send some data)
    #   - xlist - sockets to be monitored for exceptions (we want to monitor all sockets for errors, so we can use rlist)
    # Returns lists:
    #   - reading - sockets we received some data on (that way we don't have to check sockets manually)
    #   - writing - sockets ready for data to be send thru them
    #   - errors  - sockets with some exceptions
    # This is a blocking call, code execution will "wait" here and "get" notified in case any action should be taken
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

    # Iterate over notified sockets
    for notified_socket in read_sockets:

        # If notified socket is a server socket - new connection, accept it
        if notified_socket == server_socket:

            # Accept new connection
            # That gives us new socket - client socket, connected to this given client only, it's unique for that client
            # The other returned object is ip/port set
            client_socket, client_address = server_socket.accept()

            # Client should send his name right away, receive it
            user = new_user(client_socket)

            # If False - client disconnected before he sent his name
            if user is False:
                continue

            # Add accepted socket to select.select() list
            sockets_list.append(client_socket)

            # Also save username and username header
            clients[client_socket] = user

            print('Accepted new connection from {}:{}, username: {}'.format(*client_address, user['data'].decode('utf-8')))

        # Else existing socket is sending a message
        else:

            # Receive message
            message = receive_message(notified_socket)

            # If False, client disconnected, cleanup
            if message is False:
                print('Closed connection from: {}'.format(clients[notified_socket]['data'].decode('utf-8')))

                # Remove from list for socket.socket()
                sockets_list.remove(notified_socket)

                # Remove from our list of users
                del clients[notified_socket]
                continue

            # Get user by notified socket, so we will know who sent the message
            user = clients[notified_socket]

            print(f'Received message from {user["data"].decode("utf-8")} to {message["to"]}: {message["data"].decode("utf-8")}')

            # Iterate over connected clients and broadcast message

            for client_socket in clients:
                # But don't sent it to sender

                # size of user sender
                message_opcode = f"{(message['opcode']):<{MSG_OPCODE}}".encode('utf-8')
                # size of user sender
                message_from = f"{(message['from']):<{USER_LENGTH}}".encode('utf-8')
                # size of user sender
                message_to = f"{(message['to']):<{USER_LENGTH}}".encode('utf-8')

                if client_socket != notified_socket:   
                    # name of user sender
                    # usr_sender = user['data']
                    # size of sending message
                    # data_length = f"{(message['header']):<{DATA_LENGTH}}".encode('utf-8')

                    # Send user and message (both with their headers)
                    # We are reusing here message header sent by sender, and saved username header send by user when he connected
                    if message["to"] == "ALL":
                        client_socket.send(message_opcode + message_from + message_to + message['data'])

                    elif clients[client_socket]['data'].decode('utf-8') == message["to"]:
                        # target_info = str(client_socket).split("raddr=(")[1].split(")")[0].split(", ")
                        # target_ip = target_info[0]
                        # target_port = target_info[1]
                        # client_socket.send(usr_header_length + usr_sender + data_length + message['data'])
                        client_socket.send(message_opcode + message_from + message_to + message['data'])

                    else:
                        print("nao bateu: {}".format(clients[client_socket]['data']))

                elif int(message['opcode']) == 3 and client_socket == notified_socket:
                    data = f"{(message['data']).decode('utf-8'):<{DATA_LENGTH}}".encode('utf-8')
                    client_socket.send(message_opcode + message_from + message_to + message['data'])
                    break

                elif int(message['opcode']) == 4 and client_socket == notified_socket:
                    data = f"{(message['data']).decode('utf-8'):<{DATA_LENGTH}}".encode('utf-8')
                    client_socket.send(message_opcode + message_from + message_to + message['data'])
                    break

    # It's not really necessary to have this, but will handle some socket exceptions just in case
    for notified_socket in exception_sockets:

        # Remove from list for socket.socket()
        sockets_list.remove(notified_socket)

        # Remove from our list of users
        del clients[notified_socket]