# import libraries
import socket
import os
from _thread import *

# create socket
import rsa

from server.functions import handle_create_account, load_private_key

ServerSideSocket = socket.socket()
# define host and port
host = '127.0.0.1'
port = 2006

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


# handle request
def handle_client_request(req, **kwargs):
    req_type, req_parameters = req.split("###")
    if req_type == "CREATE_ACCOUNT":
        return handle_create_account(req_parameters, **kwargs)
    elif req_type == "LOGIN":
        return req_type + "*" + req_parameters
    elif req_type == "SHOW_ONLINE_USERS":
        return req_type + "*" + req_parameters
    elif req_type == "SEND_MESSAGE":
        return req_type + "*" + req_parameters
    elif req_type == "CREATE_GROUP":
        return req_type + "*" + req_parameters
    elif req_type == "ADD_USER_TO_GROUP":
        return req_type + "*" + req_parameters
    elif req_type == "GENERATE_KEY":
        return req_type + "*" + req_parameters
    elif req_type == "REFRESH_KEY":
        return req_type + "*" + req_parameters
    elif req_type == "REMOVE_USER_FROM_GROUP":
        return req_type + "*" + req_parameters
    else:
        return "ERROR: Please enter avalid request type."


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
            connection.sendall(handle_client_request(data, client_pub_key=client_pub_key))
        else:
            # # response = 'Server message: ' + data.decode('utf-8')
            # if not data:
            #     break
            connection.sendall(handle_client_request(data))
    connection.close()


while True:
    Client, address = ServerSideSocket.accept()
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    start_new_thread(multi_threaded_client, (Client,))
    ThreadCount += 1
    print('Thread Number: ' + str(ThreadCount))
ServerSideSocket.close()
