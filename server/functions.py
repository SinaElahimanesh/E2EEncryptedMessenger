import rsa
from cryptography.fernet import Fernet

from common.functions import load_public_key, rsa_encrypt
from server.server_state import state

PRIVATE_KEY_PATH = 'server_private.txt'


def __user_exists(username):
    all_usernames = list(map(lambda x: x.lower(), list(state.state['users'].keys())))
    return username.lower() in all_usernames


def load_private_key():
    with open(PRIVATE_KEY_PATH, 'rb') as file:
        key = file.read()
        return rsa.PrivateKey.load_pkcs1(key)


def handle_create_account(req_params, **kwargs):
    """
    Set up new client if username not exists.
    :param req_params: username|h(password)
    :return: Generated master key, else an empty string (bytes)
    """
    username, h_password = req_params.split('|')
    client_pub_key = kwargs['client_pub_key']
    if __user_exists(username):
        return b'UE'  # User Exist
    else:
        master_key = Fernet.generate_key()
        user = {
            'h_password': h_password,
            'master_key': master_key.decode(),
            'pub_key': client_pub_key.decode(),
            'status': True  # True for Online and False for Offline
        }
        state.state['users'][username] = user
        state.save_data()
    return rsa_encrypt(master_key.decode(),  # If everything is fine, add SU flag
                       rsa.PublicKey.load_pkcs1(client_pub_key))


def handle_login(req_params, thread_pool, socket, **kwargs):
    username, h_password = req_params.split('|')
    thread_pool.add(username, socket)
    # master_key = kwargs['master_key']
    client_pub_key = kwargs['client_pub_key']
    # fernet = Fernet(master_key)
    if username not in state.state['users']:
        return b'LO' + rsa_encrypt('USERNAME_DOES_NOT_EXISTS', rsa.PublicKey.load_pkcs1(client_pub_key))
        # return b'LO' + fernet.encrypt('USERNAME_DOES_NOT_EXISTS'.encode()) 
    elif state.state['users'][username]['h_password'] != h_password:
        return b'LO' + rsa_encrypt('PASSWORD_IS_INCORRECT', rsa.PublicKey.load_pkcs1(client_pub_key))
        # return b'LO' + fernet.encrypt('PASSWORD_IS_INCORRECT'.encode()) 
    else:
        state.state['users'][username]['status'] = True
        return b'LO' + rsa_encrypt(state.state['users'][username]['master_key'],
                                   rsa.PublicKey.load_pkcs1(client_pub_key))
        # return b'LO' + fernet.encrypt(state.state['users'][username]['master_key']) 


def handle_show_online_users(**kwargs):
    master_key = kwargs['master_key']
    fernet = Fernet(master_key)
    online_users_lst = []
    for username_key in state.state['users']:
        print('f', username_key)
        if username_key != 'status':
            if state.state['users'][username_key]['status']:
                online_users_lst.append(username_key)
                print('g', username_key, state.state['users'][username_key])
    return b'SH' + fernet.encrypt(str(online_users_lst).encode())


def handle_logout(username, **kwargs):
    master_key = kwargs['master_key']
    fernet = Fernet(master_key)
    if username not in state.state['users']:
        return b'OU' + fernet.encrypt(b'USERNAME_DOES_NOT_EXISTS'.encode())
    state.state['users']['status'] = False
    return b'OU' + fernet.encrypt('LOGOUT_SUCCESSFULLY'.encode())


def handle_send_message(req_params, **kwargs):
    thread_pool = kwargs['thread_pool']
    sender_username, receiver_username, _, _ = req_params.split('|')
    if receiver_username not in state.state['users']:
        return b'UNF', thread_pool.pool.get(sender_username)
    master_key = state.state['users'][receiver_username]['master_key'].encode()
    fernet = Fernet(master_key)
    return b'LO' + fernet.encrypt(req_params.encode()), thread_pool.pool.get(receiver_username)


def handle_refresh_key(req_params, **kwargs):
    """
    This method set a shared key between two peers A, B. It sends A's parameters to B, receive
    B's parameters and finally send them back to A.
    :param req_params: client_username|peer|nonce|public_key
    :param kwargs: master_key
    :return: B's parameters to be sent to A
    """
    username, peer, nonce, public_key, parameters = req_params.split('|')
    peer_master_key = state.state['users'][peer]['master_key'].encode()
    fernet = Fernet(peer_master_key)
    enc_request = b'NK' + fernet.encrypt(req_params.encode())

    # Send to B
    peer_connection = kwargs['peer_connection']
    print('refresh_key(peer, client_state)', enc_request)
    peer_connection.send(enc_request)


def handle_backward_key(req_params, **kwargs):
    username, peer, nonce, public_key, parameters = req_params.split('|')
    # Send back to A
    client_master_key = state.state['users'][username]['master_key'].encode()
    new_fernet = Fernet(client_master_key)

    sender_connection = kwargs['sender_connection']  # Sender = A
    response = b'SK' + new_fernet.encrypt(req_params.encode())
    sender_connection.send(response)
