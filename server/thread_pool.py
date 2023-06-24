class ThreadPool:
    def __init__(self):
        self.pool = {}  # Dictionary from usernames to their socket object

    def add(self, username, socket):
        self.pool[username] = socket

    def get(self, username):
        return self.pool.get(username, None)  # Return None if username not found
