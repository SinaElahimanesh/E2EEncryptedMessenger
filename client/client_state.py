import json

CLIENT_DATA_PATH = 'client_data.json'
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

    def load_data(self):
        with open(self.path, 'r') as file:
            self.state = json.load(file)

    def save_data(self):
        with open(self.path, 'w') as file:
            json.dump(self.state, file)


client_state = ClientState(CLIENT_DATA_PATH)
# client_state.save_data() # Run this for the first time to create a new file
client_state.load_data()
