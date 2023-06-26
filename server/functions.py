import rsa
from cryptography.fernet import Fernet

from common.functions import load_public_key, rsa_encrypt
from server.server_state import state

PRIVATE_KEY_PATH = 'server_private.txt'


def __user_exists(username):
    return username in state.state['users']


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
        master_key = state.state['users'][username]['master_key'].encode()
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
    return rsa_encrypt(master_key.decode(),
                       rsa.PublicKey.load_pkcs1(client_pub_key))


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
    peer_connection.send(enc_request)


def handle_backward_key(req_params, **kwargs):
    username, peer, nonce, public_key, parameters = req_params.split('|')
    # Send back to A
    client_master_key = state.state['users'][username]['master_key'].encode()
    new_fernet = Fernet(client_master_key)

    sender_connection = kwargs['sender_connection']  # Sender = A
    response = b'SK' + new_fernet.encrypt(req_params.encode())
    sender_connection.send(response)
