import base64
import hashlib
import rsa
from cryptography.fernet import Fernet

PUBLIC_KEY_SERVER_PATH = '../server_pub.txt'


def __rsa_encrypt(message, public):
    return rsa.encrypt(message.encode(), public)


def __save_private_key(private, username, password):
    """
    :param private: Private Key object
    :param password:
    :return: Encrypt the private key using h(password) and then saves it in a file: username.txt
    """
    sym_key = base64.urlsafe_b64encode(hashlib.sha256(password.encode('utf-8')).hexdigest()[:32].encode('utf-8'))
    fernet = Fernet(sym_key)
    encrypted_private_key = fernet.encrypt(private.save_pkcs1())
    # Save encrypted private key to a file
    with open(f'keys/private/{username}_private.txt', 'wb') as f:
        f.write(encrypted_private_key)


def __save_public_key(public, username):
    """
    :param public: Public Key object
    :return: Saves public key in a file: username.txt
    """
    # Save public key to a file
    with open(f'keys/public/{username}_public.txt', 'wb') as f:
        f.write(public.save_pkcs1())


def __load_private_key(username, password):
    """
    Use this function to load the private key from file.
    :param username:
    :param password:
    :return:
    """
    fernet_key = hashlib.sha256(password.encode('utf-8')).hexdigest()
    # Read encrypted private key from file
    with open(f'keys/private/{username}_private.txt', 'rb') as f:
        encrypted_private_key = f.read()

    # Decrypt private key using Fernet key
    cipher_suite = Fernet(fernet_key)
    decrypted_private_key = cipher_suite.decrypt(encrypted_private_key)

    # Load decrypted private key as rsa.PrivateKey object
    private_key = rsa.PrivateKey.load_pkcs1(decrypted_private_key)

    return private_key


def __load_public_key(username):
    """
    Use this function to load the public key from file.
    :param username:
    :return: Public Key object
    """
    with open(f'keys/public/{username}_public.txt', 'rb') as f:
        public_key = f.read()
    return rsa.PublicKey.load_pkcs1(public_key)


def __generate_rsa_key(username, password):
    public, private = rsa.newkeys(1024)
    __save_private_key(private, username, password)
    __save_public_key(public, username)
    return public


def create_account(username, password):
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    data = '|'.join([username, hashed_password]) + '###CREATE_ACCOUNT'
    with open(PUBLIC_KEY_SERVER_PATH, 'rb') as file:
        server_pub = rsa.PublicKey.load_pkcs1(file.read())
    return __rsa_encrypt(data, server_pub)
