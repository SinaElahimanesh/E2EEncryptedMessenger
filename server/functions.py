import rsa
from cryptography.fernet import Fernet

from common.functions import load_public_key, rsa_encrypt
from server.server_state import state

PRIVATE_KEY_PATH = '../server_private.txt'


def __user_exists(username):
    for user in state.state['users']:
        if user['username'] == username:
            return True
    return False


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
        return ''
    master_key = Fernet.generate_key()
    user = {
        'username': username,
        'h_password': h_password,
        'master_key': master_key.decode(),
        'pub_key': client_pub_key.decode(),
        'status': True  # True for Online and False for Offline
    }
    state.state['users'].append(user)
    state.save_data()
    return rsa_encrypt(master_key.decode(),
                       rsa.PublicKey.load_pkcs1(client_pub_key))
