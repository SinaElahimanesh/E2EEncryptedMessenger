# import libraries
import socket
import time
from _thread import start_new_thread
# create client socket
from cryptography.fernet import Fernet

from client.client_state import client_state, SESSION_KEY_DURATION
from client.functions import create_account, save_master_key, generate_dh_shared_key
from client.parsers import parse_create_account

ClientMultiSocket = socket.socket()

# define host and port 
host = '127.0.0.1'
port = 2006

# waiting to be connected to the server
print('Waiting for connection response')
try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

# receive the message from the server
res = ClientMultiSocket.recv(1024)

# prompt
USER_PROMPT = "\n\nHey there! You can write the following commands:\n" + "1. Create Account: Create Account [USERNAME] [PASSWORD]\n" + "2. Login: Login [USERNAME] [PASSWORD]\n" + "3. Get List of Online Users: Show Online Users\n" + "4. Send Message: Send [MESSAGE] to [USERNAME]\n" + "5. Create Group: Create Group [GROUP_NAME]\n" + "6. Add User to Group: Add [USER] to [GROUP_NAME]]\n" + "7. Remove User from Group: Remove [USER] from [GROUP_NAME]\n"


# encode message
def encode_message(inp):
    if inp.lower().startswith("1") or inp.lower().startswith("create account"):
        return "SUCCESS", inp + "###CREATE_ACCOUNT"
    elif inp.lower().startswith("2") or inp.lower().startswith("login"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("3") or inp.lower().startswith("show"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("4") or inp.lower().startswith("send"):
        return "SUCCESS", inp + "###SEND_MESSAGE"
    elif inp.lower().startswith("5") or inp.lower().startswith("create group"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("6") or inp.lower().startswith("add"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("7") or inp.lower().startswith("remove"):
        return "SUCCESS", inp + "###a"
    return "FAILURE", "Please enter a valid input"


def handle_response(response, em):
    rest, req_type = em.split('###')
    if req_type.lower().startswith('create'):
        username, password = rest.split()[2:]
        save_master_key(response, username, password)


def build_request(em):
    """
    :param em: Request type, which starts with ###. e.g: ###GENERATE_KEY
    :return: The corresponding request data to send based on request type.
  """
    if em.lower().startswith("create account"):
        username, password, public_key = parse_create_account(em)
        return create_account(username, password, public_key)


def handle_incoming_requests(connection):
    """
    This function waits for requests from the server for tasks such as key management.
    :param connection: Socket object
    """
    while True:
        cipher_text = connection.recv(2048)
        if cipher_text[0] == 83 and cipher_text[1] == 75:  # if it starts with 'SK', we have to handle set key process
            master_key = client_state.state['master_key'].encode()
            fernet = Fernet(master_key)
            # It must be in this format: (username, peer, nonce, peer_private_key)
            plain = fernet.decrypt(cipher_text).decode()
            _, peer, nonce, peer_public_key = plain.split('|')
            if nonce != client_state.state['nonce']:
                print('CAUTION: POTENTIAL REPLAY ATTACK DETECTED DUE TO NONCE MISMATCH.')
                client_state.state['nonce'] = ''
                continue
            else:
                session_key = generate_dh_shared_key(peer, peer_public_key)  # Bytes
                client_state.state['session_keys'][peer] = (session_key, time.time() + SESSION_KEY_DURATION)
        # Start a new thread for incoming requests from server


start_new_thread(handle_incoming_requests, (ClientMultiSocket,))

# send message to server regularly
while True:
    Input = input(USER_PROMPT)
    print("\n")
    flag, em = encode_message(Input)
    if flag == "SUCCESS":
        data = build_request(em)
        ClientMultiSocket.send(data)
        res = ClientMultiSocket.recv(1024)
        handle_response(res, em)
    else:
        print(em)
ClientMultiSocket.close()
