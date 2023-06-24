import base64
import hashlib

import rsa
from cryptography.fernet import Fernet


def rsa_encrypt(message, public):
    return rsa.encrypt(message.encode(), public)


def save_private_key(private, username, password):
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


def save_public_key(public, username):
    """
    :param public: Public Key object
    :return: Saves public key in a file: username.txt
    """
    # Save public key to a file
    with open(f'keys/public/{username}_public.txt', 'wb') as f:
        f.write(public.save_pkcs1())


def load_private_key(username, password):
    """
    Use this function to load the private key from file.
    :param username:
    :param password:
    :return:
    """
    fernet_key = base64.urlsafe_b64encode(hashlib.sha256(password.encode('utf-8')).hexdigest()[:32].encode('utf-8'))
    # Read encrypted private key from file
    with open(f'keys/private/{username}_private.txt', 'rb') as f:
        encrypted_private_key = f.read()

    # Decrypt private key using Fernet key
    cipher_suite = Fernet(fernet_key)
    decrypted_private_key = cipher_suite.decrypt(encrypted_private_key)

    # Load decrypted private key as rsa.PrivateKey object
    private_key = rsa.PrivateKey.load_pkcs1(decrypted_private_key)

    return private_key


def load_public_key(username):
    """
    Use this function to load the public key from file.
    :param username:
    :return: Public Key object
    """
    with open(f'../client/keys/public/{username}_public.txt', 'rb') as f:
        public_key = f.read()
    return rsa.PublicKey.load_pkcs1(public_key)
