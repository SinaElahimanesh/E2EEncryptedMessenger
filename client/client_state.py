import json
import os
from cryptography.fernet import Fernet
import base64

# CLIENT_DATA_PATH = 'client/client_data.json'
SESSION_KEY_DURATION = float(24 * 60 * 60) # In Seconds

class ClientState:
    def __init__(self, path):
        self.path = path
        self.state = {
            'master_key': [],
            'username': '',  # TODO: Username must be set after login
            'nonce': '',  # Last Generated Nonce  to be checked in key generation process
            'private_dh_keys': {},  # Mapping from receivers to clients generated private keys
            'session_keys': {}  # Mapping from receivers to a tuple: (shared session keys, timestamp)
        }
        self.chats = {
            'history': {}
        }

    def load_data(self):
        if not os.path.isfile(self.path):
            with open(self.path, 'w') as file:
                json.dump({'master_key': [], 'username': '', 'nonce': '', 'private_dh_keys': {}, 'session_keys': {}}, file)
        
        with open(self.path, 'r') as file:
            self.state = json.load(file)
    

    def save_data(self):
        with open(self.path, 'w') as file:
            json.dump(self.state, file)


    def save_chats(self, password, sender, message, username):
        fernet = Fernet(base64.urlsafe_b64encode(password))
        cipher_text = fernet.encrypt({sender, message}.encode())
        with open("client/" + username, 'w') as file:
            file.write(cipher_text)

# CLIENT_DATA_PATH = 'client/client_data.json'
# client_state = ClientState(CLIENT_DATA_PATH)
# # client_state.save_data() # Run this for the first time to create a new file
# client_state.load_data()
