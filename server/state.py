import json

SERVER_DATA_PATH = 'data.json'


class State:
    def __init__(self, path):
        self.path = path
        self.state = None

    def load_data(self):
        with open(self.path, 'r') as file:
            self.state = json.load(file)

    def save_data(self):
        with open(self.path, 'w') as file:
            json.dump(self.state, file)


state = State(SERVER_DATA_PATH)
