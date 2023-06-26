import json

SERVER_DATA_PATH = 'server/data.json'


class ServerState:
    def __init__(self, path):
        self.path = path
        self.state = {
            'users': {} # Dictionary from usernames to their attributes
        }

    def load_data(self):
        with open(self.path, 'r') as file:
            self.state = json.load(file)

    def save_data(self):
        with open(self.path, 'w') as file:
            json.dump(self.state, file)


state = ServerState(SERVER_DATA_PATH)
# state.save_data() # Run this for the first time to create a new file
state.load_data()