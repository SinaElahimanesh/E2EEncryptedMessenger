# import libraries
import socket
import os
from _thread import *

# create socket
import rsa
from cryptography.fernet import Fernet

from server.functions import handle_create_account, load_private_key, handle_refresh_key, handle_backward_key, handle_login, handle_show_online_users, handle_logout, handle_send_message
from server.server_state import state
from server.thread_pool import ThreadPool

ServerSideSocket = socket.socket()
# define host and port
host = '127.0.0.1'
port = 2011

# number of threads (number of connected clients)
ThreadCount = 0

# bind server to client
try:
    ServerSideSocket.bind((host, port))
except socket.error as e:
    print(str(e))

# server is listening
print('Socket is listening...')
ServerSideSocket.listen(5)

for username_key in state.state['users']:
    state.state['users'][username_key]['status'] = False
    state.save_data()


# handle request
def handle_client_request(req, connection, **kwargs):
    req_type, req_parameters = req.split("###")
    if req_type == "CREATE_ACCOUNT":
        return handle_create_account(req_parameters, **kwargs)
    elif req_type == "LOGIN":
        return handle_login(req_parameters, thread_pool, connection, **kwargs)
    elif req_type == "SHOW_ONLINE_USERS":
        return handle_show_online_users(**kwargs)
    elif req_type == "SEND_MESSAGE":
        return handle_send_message(req_parameters, **kwargs)
    elif req_type == "CREATE_GROUP":
        return req_type + "*" + req_parameters
    elif req_type == "ADD_USER_TO_GROUP":
        return req_type + "*" + req_parameters
    elif req_type == "BACKWARD_KEY":
        # Handle the returned key from the receiver of handshake process (B)
        username = req_parameters.split('|')[0]
        sender_connection = thread_pool.get(username)
        kwargs['sender_connection'] = sender_connection
        return handle_backward_key(req_parameters, **kwargs)
    elif req_type == "REFRESH_KEY":
        peer = req_parameters.split('|')[1]
        peer_connection = thread_pool.get(peer)
        kwargs['peer_connection'] = peer_connection
        print('refersh', req_parameters)
        handle_refresh_key(req_parameters, **kwargs)
        return None
    elif req_type == "REMOVE_USER_FROM_GROUP":
        return req_type + "*" + req_parameters
    elif req_type == "LOGOUT":
        return handle_logout(req_parameters, **kwargs)
    else:
        return "ERROR: Please enter a valid request type."


# handle client
def multi_threaded_client(connection):
    connection.send(str.encode('Server is working:'))
    private_key = load_private_key()
    while True:
        data = connection.recv(2048)
        print(data)
        if data[0] == 80 and data[1] == 85:  # If it starts with PU, it means it has been encrypted with server_pub_key
            client_pub_key = data[-251:]
            data = data[2:-251]
            data = rsa.decrypt(data, private_key).decode()
            response = handle_client_request(data, connection, client_pub_key=client_pub_key)
            connection.sendall(response)

        elif data[0] == 77 and data[1] == 75:  # If it starts with MK, it means it has been encrypted with Master Key
            length = int(data[2:5])  # Length of cipher
            cipher_text = data[-length:]
            username = data[5:-length].decode()
            if username not in state.state['users']:
                connection.sendall(b'UNF')
            else:
                master_key = state.state['users'][username]['master_key'].encode()
                fernet = Fernet(master_key)
                plain = fernet.decrypt(cipher_text).decode()
                # # response = 'Server message: ' + data.decode('utf-8')
                # if not data:
                #     break
                req_type, req_parameters = plain.split("###")
                if req_type == "SEND_MESSAGE":
                    response, receiver_connection = handle_send_message(req_parameters, thread_pool=thread_pool)
                    if response is not None:
                        receiver_connection.sendall(response)
                else:
                    response = handle_client_request(plain, connection, master_key=master_key)
                    if response is not None:
                        connection.sendall(response)
    connection.close()


thread_pool = ThreadPool()

while True:
    Client, address = ServerSideSocket.accept()
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    ThreadCount += 1
    start_new_thread(multi_threaded_client, (Client,))
    print('Thread Number: ' + str(ThreadCount))
ServerSideSocket.close()
