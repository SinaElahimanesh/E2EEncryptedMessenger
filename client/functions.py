import hashlib
import random
import rsa
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time
import base64
import hmac
from termcolor import colored
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa as asymmetricrsa
from cryptography.hazmat.backends import default_backend




# from client_main import client_state
from common.functions import save_private_key, save_public_key, rsa_encrypt, load_private_key, load_public_key
from cryptography.hazmat.primitives.asymmetric import dh

PUBLIC_KEY_SERVER_PATH = 'server_pub.txt'


def __generate_nonce():
    return str(random.randint(1, 10 ** 6))


def __generate_rsa_key(username, password):
    public, private = rsa.newkeys(1024)
    save_private_key(private, username, password)
    save_public_key(public, username)
    return public


def generate_dh_keys(g, size, peer, client_state, parameters=None):
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


def generate_dh_shared_key(my_key, peer_public_key, client_state):
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


def save_master_key(response, username, password, client_state):
    private_key = load_private_key(username, password)
    master_key = rsa.decrypt(response, private_key).decode()
    client_state.state['master_key'] = master_key
    client_state.save_data()


def save_master_key_login(master_key, client_state):
    client_state.state['master_key'] = master_key
    client_state.save_data()


def create_account(username, password, public_key):
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    data = 'CREATE_ACCOUNT###' + '|'.join([username, hashed_password])
    with open(PUBLIC_KEY_SERVER_PATH, 'rb') as file:
        server_pub = rsa.PublicKey.load_pkcs1(file.read())
    return b'PU' + rsa_encrypt(data, server_pub) + public_key.save_pkcs1()


def create_group(group_name, client_state):
    data = 'CREATE_GROUP###' + '|'.join([group_name, client_state.state['username']])
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + client_state.state['username'].encode() + cipher_text


# def login(username, password, client_state):
#     hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
#     data = 'LOGIN###' + '|'.join([username, hashed_password])
#     master_key = client_state.state['master_key'].encode()
#     fernet = Fernet(master_key)
#     cipher_text = fernet.encrypt(data.encode())
#     length = "{:03d}".format(len(cipher_text)).encode()
#     return b'CG' + length + username.encode() + cipher_text


def login(username, password, public_key):
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    data = 'LOGIN###' + '|'.join([username, hashed_password])
    with open(PUBLIC_KEY_SERVER_PATH, 'rb') as file:
        server_pub = rsa.PublicKey.load_pkcs1(file.read())
    return b'PU' + rsa_encrypt(data, server_pub) + public_key.save_pkcs1()
    # master_key = client_state.state['master_key'].encode()
    # fernet = Fernet(master_key)
    # cipher_text = fernet.encrypt(data.encode())
    # length = "{:03d}".format(len(cipher_text)).encode()
    # return b'MK' + length + username.encode() + cipher_text


def show_online_users(em, client_state):
    data = 'SHOW_ONLINE_USERS###' + client_state.state['username']
    username = client_state.state['username']
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + username.encode() + cipher_text


def show_my_groups(em, client_state):
    data = 'SHOW_GROUPS###' + client_state.state['username']
    username = client_state.state['username']
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + username.encode() + cipher_text


def logout(em, client_state):
    data = 'LOGOUT###' + client_state.state['username']
    username = client_state.state['username']
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + username.encode() + cipher_text



def generate_signature(message, username, password):
    private_key = load_private_key(username, password)
    if isinstance(message, str):
        message = message.encode('utf-8')
    elif hasattr(message, "read") and hasattr(message.read, "__call__"):
        message = message.read()

    hash_value = hashlib.sha256(message).digest()
    signature = rsa.sign(hash_value, private_key, 'SHA-256')
    return signature

def verify_signature(message, signature, username):
    public_key = load_public_key(username)
    if isinstance(message, str):
        message = message.encode('utf-8')
    elif hasattr(message, "read") and hasattr(message.read, "__call__"):
        message = message.read()

    hash_value = hashlib.sha256(message).digest()
    try:
        rsa.verify(hash_value, signature, public_key)
        return True
    except rsa.VerificationError:
        return False



# def generate_signature(message, username, password):
#     private_key = load_private_key(username, password)
#     signature = rsa.sign(message, private_key, 'SHA-256')
#     return signature


# def verify_signature(message, signature, username):
#     public_key = load_public_key(username)
#     try:
#         rsa.verify(message, signature, public_key)
#         return True
#     except rsa.VerificationError:
#         return False



# def generate_signature(message, username, password):
#     # Load the private key
#     private_key = load_private_key(username, password)
#     # private_key = asymmetricrsa.RSAPrivateKey.from_pem(private_key)


#     # Sign the message
#     signature = private_key.sign(
#         message.encode(),
#         padding.PSS(
#             mgf=padding.MGF1(hashes.SHA256()),
#             salt_length=padding.PSS.MAX_LENGTH
#         ),
#         hashes.SHA256()
#     )
#     print(signature, type(signature))
#     return signature


# def verify_signature(message, signature, username):
#     # Load the public key
#     public_key = load_public_key(username)
#     # public_key = asymmetricrsa.RSAPublicKey.from_pem(public_key)


#     try:
#         # Verify the signature
#         public_key.verify(
#             signature,
#             message.encode(),
#             padding.PSS(
#                 mgf=padding.MGF1(hashes.SHA256()),
#                 salt_length=padding.PSS.MAX_LENGTH
#             ),
#             hashes.SHA256()
#         )
#         return True
#     except:
#         return False



def send_message(sender_username, receiver_username, message, client_state, connection, password):
    if 'session_keys' not in client_state.state or receiver_username not in client_state.state['session_keys'] or \
            client_state.state['session_keys'][receiver_username][1] >= time.time():
        request = refresh_key(receiver_username, client_state)
        connection.send(request)
        time.sleep(0.3)
    session_key = base64.urlsafe_b64encode(client_state.state['session_keys'][receiver_username][0])
    emoji_key = map_key_to_emoji(session_key)
    print(colored('THIS SESSION IS ENCRYPTED:'+ emoji_key, 'green'))
    session_fernet = Fernet(session_key)
    cipher_message = session_fernet.encrypt(message.encode())

    # Create HMAC
    hmac_tag = create_hmac(session_key, message.encode())
    # print('this is ', str(cipher_message), str(hmac_tag))
    data = 'SEND_MESSAGE###' + '**'.join([sender_username, receiver_username, str(cipher_message), str(hmac_tag), str(generate_signature(message, sender_username, password))]) #generate_signature(message, sender_username, password)
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + sender_username.encode() + cipher_text


def send_group_message(username, group, message, client_state, connection, password):
    request = get_group_users(group, client_state)
    connection.send(request)
    time.sleep(0.2)
    # print(client_state.group_members)
    for user in client_state.group_members:
        if user != username:
            connection.send(send_message(username, user, str('(' + group + ' group) '+ message), client_state, connection, password))
    print(colored('Sent successfully.', 'green'))
    return



def get_group_users(group_name, client_state):
    data = 'GROUP_USERS###' + '|'.join([group_name])
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + client_state.state['username'].encode() + cipher_text



def add_to_group(username, new_member, group_username, client_state, connection):
    if 'session_keys' not in client_state.state or new_member not in client_state.state['session_keys'] or \
        client_state.state['session_keys'][new_member][1] >= time.time():
        request = refresh_key(new_member, client_state)
        connection.send(request)
        time.sleep(0.3)
    # session_key = base64.urlsafe_b64encode(client_state.state['session_keys'][new_member][0])
    # group_session_key = client_state.state['group_session_keys'][group_username].encode()
    # session_fernet = Fernet(session_key)
    # group_session_key_encrypted = session_fernet.encrypt(group_session_key)
    # data = 'ADD###' + '|'.join([username, group_username, new_member, str(group_session_key_encrypted)])
    data = 'ADD###' + '|'.join([username, group_username, new_member])

    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + username.encode() + cipher_text


def remove_from_group(username, remove_username, group_username, client_state, connection):
    if 'session_keys' not in client_state.state or remove_username not in client_state.state['session_keys'] or \
        client_state.state['session_keys'][remove_username][1] >= time.time():
        request = refresh_key(remove_username, client_state)
        connection.send(request)
        time.sleep(0.3)

    data = 'REMOVE###' + '|'.join([username, group_username, remove_username])

    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + username.encode() + cipher_text


emoji_map = {
    "A": "😀",
    "B": "😎",
    "C": "🐼",
    "D": "🌈",
    "E": "🍕",
    "F": "🎉",
    "G": "🌻",
    "H": "🚀",
    "I": "🌟",
    "J": "🐬",
    "K": "🍦",
    "L": "🦄",
    "M": "🐝",
    "N": "🌺",
    "O": "🌞",
    "P": "🍓",
    "Q": "🎈",
    "R": "🔥",
    "S": "🐢",
    "T": "🚲",
    "U": "⭐",
    "V": "🍀",
    "W": "🌊",
    "X": "🌙",
    "Y": "🌸",
    "Z": "🍩"
}

def map_key_to_emoji(master_key):
    emoji_key = ""
    for char in master_key.decode():
        if len(emoji_key) == 3:
            break
        if char.isalpha():
            if char.upper() in emoji_map:
                emoji_key += emoji_map[char.upper()]
            else:
                emoji_key += char
    return emoji_key

def refresh_key(peer, client_state):
    """
    :param peer: peer username
    :return: The corresponding request to be sent(bytes), nonce(string), dh private key
    """
    # Prepare data
    client_username = client_state.state['username']
    nonce = __generate_nonce()
    client_state.state['nonce'] = nonce
    private_key, public_key, parameters = generate_dh_keys(2, 512, peer, client_state)
    data = 'REFRESH_KEY###' + '|'.join([client_username, peer, nonce, public_key, parameters])

    # Apply encryption
    master_key = client_state.state['master_key'].encode()
    fernet = Fernet(master_key)
    cipher_text = fernet.encrypt(data.encode())
    length = "{:03d}".format(len(cipher_text)).encode()
    return b'MK' + length + client_username.encode() + cipher_text


def is_password_strong(password):
    # return True # TODO: DELETE THIS LINE FOR PRESENTATION TIME
    # Check length
    if len(password) < 8:
        return False

    # Check for at least one uppercase letter
    if not any(char.isupper() for char in password):
        return False

    # Check for at least one lowercase letter
    if not any(char.islower() for char in password):
        return False

    # Check for at least one digit
    if not any(char.isdigit() for char in password):
        return False

    # Check for at least one special character
    special_characters = "!@#$%^&*()-_=+[]{}|;:,.<>/?"
    if not any(char in special_characters for char in password):
        return False

    # If all checks pass, the password is strong
    return True


# Function to create HMAC
def create_hmac(key, message):
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    return hmac_obj.digest()

# Function to verify HMAC
def verify_hmac(key, message, hmac_tag):
    hmac_obj = hmac.new(key, message, hashlib.sha256)
    generated_hmac_tag = hmac_obj.digest()

    if hmac.compare_digest(generated_hmac_tag, hmac_tag):
        return True
    else:
        return False

