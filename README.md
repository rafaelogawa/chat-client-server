# Chat-Client-Server


PS D:\git\chat-client-server> python .\server.py
Listening for connections on 127.0.0.1:1234...
Accepted new connection from 127.0.0.1:53863, username: a
Accepted new connection from 127.0.0.1:53864, username: s
message_to: a
Received message from s to a: dasdasdasdasdasda
client_socket: <socket.socket fd=368, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('127.0.0.1', 1234), raddr=('127.0.0.1', 53863)>


target_ip: '127.0.0.1'


target_port: 53863


clients: {<socket.socket fd=368, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('127.0.0.1', 1234), raddr=('127.0.0.1', 53863)>: {'header': b'1         ', 'data': b'a'}, <socket.socket fd=420, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0, laddr=('127.0.0.1', 1234), raddr=('127.0.0.1', 53864)>: {'header': b'1         ', 'data': b's'}}


clients[client_socket]: {'header': b'1         ', 'data': b'a'}


clients[client_socket]['data']: b'a'


user['header']: b'1         '


user['data']: b's'


message['data']: b'dasdasdasdasdasda'