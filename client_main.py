# import libraries
import socket
import time
from threading import Thread
import sys
from termcolor import colored
# create client socket
from cryptography.fernet import Fernet
from termcolor import colored
import ast

from client.client_state import SESSION_KEY_DURATION, ClientState
from client.functions import create_account, create_group, save_master_key, generate_dh_shared_key, generate_dh_keys, refresh_key, login, show_online_users, logout, send_message
from client.parsers import parse_create_account, parse_create_group, parse_login, parse_send_message
from common.functions import load_public_key

# If the received message from the server is corresponded to a sent message,
# we need the message to know how to handle that!
MOST_RECENT_ENCODED_MESSAGE = ''

# Initialize Client Socket
ClientMultiSocket = socket.socket()

# define host and port
host = '127.0.0.1'
port = 2011

CLIENT_DATA_PATH = sys.argv[1]


client_state = ClientState(CLIENT_DATA_PATH)
# client_state.load_data()


# waiting to be connected to the server
print('Waiting for connection response')
try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

# receive the message from the server
res = ClientMultiSocket.recv(1024)

# prompt
USER_PROMPT = "\n\nHey there! You can write the following commands:\n" + "1. Create Account: Create Account [USERNAME] [PASSWORD]\n" + "2. Login: Login [USERNAME] [PASSWORD]\n" + "3. Get List of Online Users: Show Online Users\n" + "4. Send Message: Send [MESSAGE] to [USERNAME]\n" + "5. Create Group: Create Group [GROUP_NAME]\n" + "6. Add User to Group: Add [USER] to [GROUP_NAME]]\n" + "7. Remove User from Group: Remove [USER] from [GROUP_NAME]\n" + "8. Logout From Account: Logout\n"


# encode message
def encode_message(inp):
    if client_state.state['username'] == '' and (not inp.lower().startswith("2") and not inp.lower().startswith("login")) and (not inp.lower().startswith("1") and not inp.lower().startswith("create account")):
        return "FAILURE", "Please login first."
    if inp.lower().startswith("1") or inp.lower().startswith("create account"):
        return "SUCCESS", inp + "###CREATE_ACCOUNT"
    elif inp.lower().startswith("2") or inp.lower().startswith("login"):
        return "SUCCESS", inp + "###LOGIN"
    elif inp.lower().startswith("3") or inp.lower().startswith("show"):
        return "SUCCESS", inp + "###SHOW_ONLINE_USERS"
    elif inp.lower().startswith("4") or inp.lower().startswith("send"):
        return "SUCCESS", inp + "###SEND_MESSAGE"
    elif inp.lower().startswith("5") or inp.lower().startswith("create group"):
        return "SUCCESS", inp + "###CREATE_GROUP"
        return "SUCCESS", inp + "###CREATE_GROUP"
    elif inp.lower().startswith("6") or inp.lower().startswith("add"):
        return "SUCCESS", inp + "###ADD"
        return "SUCCESS", inp + "###ADD"
    elif inp.lower().startswith("7") or inp.lower().startswith("remove"):
        return "SUCCESS", inp + "###REMOVE"
        return "SUCCESS", inp + "###REMOVE"
    elif inp.lower().startswith("8") or inp.lower().startswith("logout"):
        return "SUCCESS", inp + "###LOGOUT"
    return "FAILURE", "Please enter a valid input"


def handle_response(response, em):
    global MOST_RECENT_ENCODED_MESSAGE
    rest, req_type = em.split('###')
    MOST_RECENT_ENCODED_MESSAGE = ''
    if req_type.lower().startswith('create'):
        username, password = rest.split()[2:]
        save_master_key(response, username, password, client_state)
    if req_type.lower().startswith('login'):
        masterkey = response[2:]
        username, password = rest.split()[1:]
        
        if response == 'USERNAME_DOES_NOT_EXISTS' or response == 'PASSWORD_IS_INCORRECT':
            print(colored('USERNAME OR PASSWORD IS INCORRECT.', 'red'))
        else:
            client_state.state['username'] = username
            # client_state.save_data()
            print(colored('Login successfully.', 'green'))
        save_master_key(masterkey, username, password, client_state)


def build_request(em, connection):
    """
    :param em: Request type, which starts with ###. e.g: ###GENERATE_KEY
    :return: The corresponding request data to send based on request type.
  """
    if em.lower().startswith("create account"):
        username, password, public_key = parse_create_account(em)
        return create_account(username, password, public_key)
    elif em.lower().startswith("create group"):
        group_name = parse_create_group(em)
        return create_group(group_name)
    elif em.lower().startswith("create group"):
        group_name = parse_create_group(em)
        return create_group(group_name)
    elif em.lower().startswith("login"):
        username, password = parse_login(em)
        public_key = load_public_key(username)
        if public_key == 'ERR':
            return 'ERR'
        return login(username, password, public_key)
    elif em.lower().startswith("show"):
        return show_online_users(em, client_state)
    elif em.lower().startswith("logout"):
        return logout(em, client_state)
    elif em.lower().startswith("send"):
        username = client_state.state['username']
        receiver_username, message = parse_send_message(em, username)
        return send_message(username, receiver_username, message, client_state, connection)



# Start a new thread for incoming requests from server

def handle_incoming_requests(connection):
    """
    This function waits for requests from the server for tasks such as key management.
    :param connection: Socket object
    """
    while True:
        cipher_text = connection.recv(2048)
        if cipher_text == b'':
            continue
        if cipher_text[0] == 85 and cipher_text[1] == 78 and cipher_text[2] == 70: 
            print(colored('USERNAME DOES NOT FOUND.', 'red'))
        elif cipher_text[0] == 83 and cipher_text[1] == 75:  # if it starts with 'SK', we have to handle set key process
            cipher_text = cipher_text[2:]
            master_key = client_state.state['master_key'].encode()
            fernet = Fernet(master_key)
            # It must be in this format: (username, peer, nonce, peer_private_key)
            plain = fernet.decrypt(cipher_text).decode()
            _, peer, nonce, peer_public_key, parameters = plain.split('|')
            if nonce != client_state.state['nonce']:
                print(colored('CAUTION: POTENTIAL REPLAY ATTACK DETECTED DUE TO NONCE MISMATCH.', 'red'))
                client_state.state['nonce'] = ''
                continue
            else:
                my_private_key = client_state.state['private_dh_keys'][peer]
                session_key = generate_dh_shared_key(my_private_key, peer_public_key.encode(), client_state)  # Bytes
                client_state.state['session_keys'][peer] = (session_key, time.time() + SESSION_KEY_DURATION)
        # if it starts with 'NK', we have to handle new key generation for a peer process.
        elif cipher_text[0] == 78 and cipher_text[1] == 75:
            cipher_text = cipher_text[2:]
            master_key = client_state.state['master_key'].encode()
            fernet = Fernet(master_key)
            # It must be in this format: (username, peer, nonce, peer_private_key)
            plain = fernet.decrypt(cipher_text).decode()
            peer, me, nonce, peer_public_key, parameters = plain.split('|')
            my_private_key, my_public_key, _ = generate_dh_keys(2, 512, peer, client_state, parameters)
            session_key = generate_dh_shared_key(my_private_key, peer_public_key.encode(), client_state)  # Bytes
            client_state.state['session_keys'][peer] = (session_key, time.time() + SESSION_KEY_DURATION)
            # Send back key to the server
            data = 'BACKWARD_KEY###' + '|'.join([peer, me, nonce, my_public_key, parameters])
            cipher_text = fernet.encrypt(data.encode())
            length = "{:03d}".format(len(cipher_text)).encode()
            connection.send(b'MK' + length + me.encode() + cipher_text)
        # elif cipher_text[0] == 76 and cipher_text[1] == 79:  # if it starts with 'LO', we have to handle set key process
        #     cipher_text = cipher_text[2:]
        #     master_key = client_state.state['master_key'].encode()
        #     fernet = Fernet(master_key)
        #     # It must be in this format: (username, peer, nonce, peer_private_key)
        #     plain = fernet.decrypt(cipher_text).decode()
        #     resp = plain.split('|')
        #     resp = resp[0]
        #     if resp == 'USERNAME_DOES_NOT_EXISTS' or resp == 'PASSWORD_IS_INCORRECT':
        #         print('Username or password is incorrect.')
        #     else:
        #         client_state.state['username'] = resp
        #         client_state.save_data()
        #         print('Login successfully.')
        elif cipher_text[0] == 83 and cipher_text[1] == 72:  # if it starts with 'SH', we have to handle set key process
            cipher_text = cipher_text[2:]
            master_key = client_state.state['master_key'].encode()
            fernet = Fernet(master_key)
            # It must be in this format: (username, peer, nonce, peer_private_key)
            plain = fernet.decrypt(cipher_text).decode()
            print(colored('List of online users:', 'green'))
            for u in ast.literal_eval(plain):
                print(colored(u, 'green'))
        elif cipher_text[0] == 79 and cipher_text[1] == 85:  # if it starts with 'OU', we have to handle set key process
            cipher_text = cipher_text[2:]
            master_key = client_state.state['master_key'].encode()
            fernet = Fernet(master_key)
            # It must be in this format: (username, peer, nonce, peer_private_key)
            plain = fernet.decrypt(cipher_text).decode()
            client_state.state['username'] = ''
            # client_state.save_data()
            if plain == 'USERNAME_DOES_NOT_EXISTS':
                print(colored('USERNAME DOES NOT FOUND.', 'red'))
            elif plain == 'LOGOUT_SUCCESSFULLY':
                print(colored('Logout successfully.', 'green'))
        elif MOST_RECENT_ENCODED_MESSAGE == '':
            cipher_text = cipher_text[2:]
            master_key = client_state.state['master_key'].encode()
            fernet = Fernet(master_key)
            plain = fernet.decrypt(cipher_text).decode()
            sender, _, m = plain.split('|')
            print(colored(f'A Message From {sender}: {m}', 'cyan'))
        else:
            handle_response(cipher_text, MOST_RECENT_ENCODED_MESSAGE)
            # connection.send(refresh_key('B'))


def handle_user_inputs(connection):
    # send message to server regularly
    global MOST_RECENT_ENCODED_MESSAGE
    while True:
        time.sleep(0.5)
        Input = input(USER_PROMPT)
        print("\n")
        flag, em = encode_message(Input)
        MOST_RECENT_ENCODED_MESSAGE = em
        if flag == "SUCCESS":
            data = build_request(em, connection)
            if data == 'ERR':
                print(colored('USERNAME DOES NOT FOUND.', 'red'))
            else:
                connection.send(data)
        else:
            print(em)
    # connection.close()


thread_1 = Thread(target=handle_user_inputs, args=(ClientMultiSocket,))
thread_1.start()
thread_2 = Thread(target=handle_incoming_requests, args=(ClientMultiSocket,))
thread_2.start()
thread_1.join()
thread_2.join()
