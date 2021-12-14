import socket, sys, threading
import select
import errno
from config import *

IP = "127.0.0.1"
PORT = 1234
my_username = input("Username: ")

# Create a socket
# socket.AF_INET - address family, IPv4, some otehr possible are AF_INET6, AF_BLUETOOTH, AF_UNIX
# socket.SOCK_STREAM - TCP, conection-based, socket.SOCK_DGRAM - UDP, connectionless, datagrams, socket.SOCK_RAW - raw IP packets
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to a given ip and port
client_socket.connect((IP, PORT))

# Set connection to non-blocking state, so .recv() call won;t block, just return some exception we'll handle
client_socket.setblocking(False)

# Prepare username and header and send them
# We need to encode username to bytes, then count number of bytes and prepare header of fixed size, that we encode to bytes as well
username = my_username.encode('utf-8')
username_header = f"{len(username):<{DATA_LENGTH}}".encode('utf-8')
client_socket.send(username_header + username)

valid_options = ['1', '2', '3']

def wait_server_answer():
    print("waiting ...")

def receive():
    while(1):
        try:
            # Now we want to loop over received messages (there might be more than one) and print them
            while True:
                # Receive our "header" containing username length, it's size is defined and constant
                message_opcode = client_socket.recv(MSG_OPCODE).decode('utf-8').strip()
                print("message_opcode: {}".format(message_opcode))

                # If we received no data, server gracefully closed a connection, for example using socket.close() or socket.shutdown(socket.SHUT_RDWR)
                if not message_opcode:
                    print('Connection closed by the server')
                    sys.exit()

                message_from = client_socket.recv(USER_LENGTH).decode('utf-8').strip()
                print("message_from: {}".format(message_from))

                message_to = client_socket.recv(USER_LENGTH).decode('utf-8').strip()
                print("message_to: {}".format(message_to))

                data = client_socket.recv(DATA_LENGTH).decode('utf-8').strip()
                print("data: {}".format(data))

                # Convert header to int value
                # username_length = int(username_header.decode('utf-8').strip())
                # print("username_length: {}".format(username_length))

                # Receive and decode username
                # username = client_socket.recv(username_length).decode('utf-8')
                # print("username: {}".format(username))

                # Now do the same for message (as we received username, we received whole message, there's no need to check if it has any length)
                # message_header = client_socket.recv(DATA_LENGTH)
                # print("message_header: {}".format(message_header))
                # message_length = int(message_header.decode('utf-8').strip())
                # print("message_length: {}".format(message_length))
                # message = client_socket.recv(message_length).decode('utf-8')
                # print("message: {}".format(message))

                # Print message
                if(int(message_opcode) == 1):
                    message_type = "pv"
                elif(int(message_opcode) == 2):
                    message_type = "all"
                elif(int(message_opcode) == 3):
                    message_type = "info"
                

                print(f'{message_from} ({message_type}) > {data}')

        except IOError as e:
            # This is normal on non blocking connections - when there are no incoming data error is going to be raised
            # Some operating systems will indicate that using AGAIN, and some using WOULDBLOCK error code
            # We are going to check for both - if one of them - that's expected, means no incoming data, continue as normal
            # If we got different error code - something happened
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print('Reading error: {}'.format(str(e)))
                sys.exit()

        except Exception as e:
            # Any other exception - something happened, exit
            print('Reading error: '.format(str(e)))
            sys.exit()

def send():
    while(1):
        try:
            print("Type Message type: 1 for broadcast, 2 for private massage:")
            message_opcode = input(f'{my_username} > ')

            if message_opcode not in valid_options:
                pass

            if(message_opcode == '1'):
                message = input(f'{my_username} > '+ "Message broadcast:")
                message_to = "ALL"

            if(message_opcode == '2'):
                message_to = input(f'{my_username} > ' + "Private Message to: ")
                message = input(f'{my_username} > ' + "Message: ")

            if message_opcode == '1':
                if message :
                    # print(username)
                    # print(f"{(username).decode('utf-8'):<{USER_LENGTH}}")
                    # print("\n")
                    # print(f"{(username).decode('utf-8'):<{USER_LENGTH}}".encode('utf-8'))
                    # print("\n")
                    # print(f"{(message_to):<{USER_LENGTH}}".encode('utf-8'))
                    # print("\n")
                    # print(f"{(message):<{DATA_LENGTH}}".encode('utf-8'))

                    # Encode message to bytes, prepare header and convert to bytes, like for username above, then send
                    message_opcode = bytes(message_opcode, 'utf-8')
                    message_from = f"{(username).decode('utf-8'):<{USER_LENGTH}}".encode('utf-8')
                    message_to = f"{(message_to):<{USER_LENGTH}}".encode('utf-8')
                    message = f"{(message):<{DATA_LENGTH}}".encode('utf-8')
                    client_socket.send(message_opcode + message_from + message_to + message)

            if message_opcode == '2':
                if message:
                    message_opcode = bytes(message_opcode, 'utf-8')
                    message_from = f"{(username).decode('utf-8'):<{USER_LENGTH}}".encode('utf-8')
                    message_to = f"{(message_to):<{USER_LENGTH}}".encode('utf-8')
                    message = f"{(message):<{DATA_LENGTH}}".encode('utf-8')
                    client_socket.send(message_opcode + message_from + message_to + message)
            
            if message_opcode == '3':
                message_opcode = bytes(message_opcode, 'utf-8')
                empty_data = f"{'':<{USER_LENGTH + DATA_LENGTH}}".encode('utf-8')
                message_from = f"{(username).decode('utf-8'):<{USER_LENGTH}}".encode('utf-8')
                client_socket.send(message_opcode + message_from + empty_data)
                wait_server_answer()

            if message_opcode == '4':
                message_opcode = bytes(message_opcode, 'utf-8')
                empty_data = f"{'':<{USER_LENGTH + DATA_LENGTH}}".encode('utf-8')
                message_from = f"{(username).decode('utf-8'):<{USER_LENGTH}}".encode('utf-8')
                client_socket.send(message_opcode + message_from + empty_data)
                wait_server_answer()

        except Exception as e:
            print(str(e))

def main():
    print("Initializating client")

    rec = threading.Thread(target=receive)
    rec.start()
    print("Initializating rec")

    sen = threading.Thread(target=send)
    sen.start()
    print("Initializating sen")

if __name__ == "__main__":
    main()