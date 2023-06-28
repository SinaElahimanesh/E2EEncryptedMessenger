import hashlib
import random
import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from client.client_state import client_state
from common.functions import save_private_key, save_public_key, rsa_encrypt, load_private_key
from cryptography.hazmat.primitives.asymmetric import dh

PUBLIC_KEY_SERVER_PATH = 'server_pub.txt'


def __generate_nonce():
    return str(random.randint(1, 10 ** 6))


def __generate_rsa_key(username, password):
    public, private = rsa.newkeys(1024)
    save_private_key(private, username, password)
    save_public_key(public, username)
    return public


def generate_dh_keys(g, size, peer, parameters=None):
    if parameters is None:
        parameters = dh.generate_parameters(generator=g, key_size=size, backend=default_backend())
    else:
        parameters = serialization.load_pem_parameters(parameters.encode())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    parameters_string = parameters.parameter_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.ParameterFormat.PKCS3).decode()
    # Update client state
    client_state.state['private_dh_keys'][peer] = private_key
    return private_key, public_key, parameters_string


def generate_dh_shared_key(my_key, peer_public_key):
    peer_key_obj = serialization.load_pem_public_key(
        peer_public_key,
        backend=default_backend()
    )
    shared_key = my_key.exchange(peer_key_obj)
    # Perform key derivation.
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key


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


def login(username, password):
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    data = 'LOGIN###' + '|'.join([username, hashed_password])
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + username.encode() + cipher_text


def show_online_users(em):
    data = 'SHOW_ONLINE_USERS###' + client_state.state['username']
    username = client_state.state['username']
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + username.encode() + cipher_text


def logout(em):
    data = 'LOGOUT###' + client_state.state['username']
    username = client_state.state['username']
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + username.encode() + cipher_text


def send_message(sender_username, receiver_username, message):
    data = 'SEND_MESSAGE###' + '|'.join([sender_username, receiver_username, message])
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + sender_username.encode() + cipher_text


def refresh_key(peer):
    """
    :param peer: peer username
    :return: The corresponding request to be sent(bytes), nonce(string), dh private key
    """
    # Prepare data
    client_username = client_state.state['username']
    nonce = __generate_nonce()
    client_state.state['nonce'] = nonce
    private_key, public_key, parameters = generate_dh_keys(2, 512, peer)
    data = 'REFRESH_KEY###' + '|'.join([client_username, peer, nonce, public_key, parameters])

    # Apply encryption
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + client_username.encode() + cipher_text
