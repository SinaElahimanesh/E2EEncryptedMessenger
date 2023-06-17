# import libraries
import socket

# create client socket
ClientMultiSocket = socket.socket()

# define host and port 
host = '127.0.0.1'
port = 2006

# waiting to be connected to the server
print('Waiting for connection response')
try:
    ClientMultiSocket.connect((host, port))
except socket.error as e:
    print(str(e))

# receive the message from the server
res = ClientMultiSocket.recv(1024)

# prompt
USER_PROMPT = "\n\nHey there! You can write the following commands:\n" + "1. Create Account: Create Account [USERNAME] [PASSWORD]\n" + "2. Login: Login [USERNAME] [PASSWORD]\n" + "3. Get List of Online Users: Show Online Users\n" + "4. Send Message: Send [MESSAGE] to [USERNAME]\n" + "5. Create Group: Create Group [GROUP_NAME]\n" + "6. Add User to Group: Add [USER] to [GROUP_NAME]]\n" + "7. Remove User from Group: Remove [USER] from [GROUP_NAME]\n"

# encode message
def encode_message(inp):
    if inp.lower().startswith("1") or inp.lower().startswith("create account"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("2") or inp.lower().startswith("login"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("3") or inp.lower().startswith("show"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("4") or inp.lower().startswith("send"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("5") or inp.lower().startswith("create group"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("6") or inp.lower().startswith("add"):
        return "SUCCESS", inp + "###a"
    elif inp.lower().startswith("7") or inp.lower().startswith("remove"):
        return "SUCCESS", inp + "###a"
    return "FAILURE", "Please enter a valid input"
    

# send message to server regularly
while True:
    Input = input(USER_PROMPT)
    print("\n")
    flag, em = encode_message(Input)
    if flag == "SUCCESS":
        ClientMultiSocket.send(str.encode(em))
        res = ClientMultiSocket.recv(1024)
        print(res.decode('utf-8'))
    else:
        print(em)
ClientMultiSocket.close()