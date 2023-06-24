import hashlib

import rsa

from client.client_state import client_state
from common.functions import save_private_key, save_public_key, rsa_encrypt, load_private_key

PUBLIC_KEY_SERVER_PATH = '../server_pub.txt'


def __generate_rsa_key(username, password):
    public, private = rsa.newkeys(1024)
    save_private_key(private, username, password)
    save_public_key(public, username)
    return public


def save_master_key(response, username, password):
    private_key = load_private_key(username, password)
    master_key = rsa.decrypt(response, private_key).decode()
    client_state.state['master_key'] = master_key
    client_state.save_data()


def create_account(username, password, public_key):
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    data = 'CREATE_ACCOUNT###' + '|'.join([username, hashed_password])
    with open(PUBLIC_KEY_SERVER_PATH, 'rb') as file:
        server_pub = rsa.PublicKey.load_pkcs1(file.read())
    return b'PU' + rsa_encrypt(data, server_pub) + public_key.save_pkcs1()
