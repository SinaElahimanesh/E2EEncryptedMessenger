import rsa
from cryptography.fernet import Fernet
import base64
import hashlib

from common.functions import load_public_key, rsa_encrypt
from server.server_state import state

PRIVATE_KEY_PATH = 'server_private.txt'


def __user_exists(username):
    all_usernames = list(map(lambda x: x.lower(), list(state.state['users'].keys())))
    return username.lower() in all_usernames


def load_private_key():
    with open(PRIVATE_KEY_PATH, 'rb') as file:
        key = file.read()
        return rsa.PrivateKey.load_pkcs1(key)


def handle_create_account(req_params, **kwargs):
    """
    Set up new client if username not exists.
    :param req_params: username|h(password)
    :return: Generated master key, else an empty string (bytes)
    """
    username, h_password = req_params.split('|')
    client_pub_key = kwargs['client_pub_key']
    if __user_exists(username):
        return b'UE'  # User Exist
    else:
        master_key = Fernet.generate_key()
        user = {
            'h_password': h_password,
            'master_key': master_key.decode(),
            'pub_key': client_pub_key.decode(),
            'status': True  # True for Online and False for Offline
        }
        state.state['users'][username] = user
        state.save_data()
    return rsa_encrypt(master_key.decode(),  # If everything is fine, add SU flag
                       rsa.PublicKey.load_pkcs1(client_pub_key))


def handle_login(req_params, thread_pool, socket, **kwargs):
    username, h_password = req_params.split('|')
    thread_pool.add(username, socket)
    # master_key = kwargs['master_key']
    client_pub_key = kwargs['client_pub_key']
    # fernet = Fernet(master_key)
    fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(h_password.encode('utf-8')).hexdigest()[:32].encode('utf-8')))
    if username not in state.state['users']:
        # return b'LO' +  rsa_encrypt('USERNAME_DOES_NOT_EXISTS', rsa.PublicKey.load_pkcs1(client_pub_key))
        return b'LO' + fernet.encrypt('USERNAME_DOES_NOT_EXISTS'.encode()) 
    elif state.state['users'][username]['h_password'] != h_password:
        # return b'LO' + rsa_encrypt('PASSWORD_IS_INCORRECT', rsa.PublicKey.load_pkcs1(client_pub_key))
        return b'LO' + fernet.encrypt('PASSWORD_IS_INCORRECT'.encode()) 
    else:
        state.state['users'][username]['status'] = True
        # return b'LO' + rsa_encrypt(state.state['users'][username]['master_key'],
        #                            rsa.PublicKey.load_pkcs1(client_pub_key))
        return b'LO' + fernet.encrypt(state.state['users'][username]['master_key'].encode()) 


def handle_show_online_users(**kwargs):
    master_key = kwargs['master_key']
    fernet = Fernet(master_key)
    online_users_lst = []
    for username_key in state.state['users']:
        if username_key != 'status':
            if state.state['users'][username_key]['status']:
                online_users_lst.append(username_key)
                # print('g', username_key, state.state['users'][username_key])
    return b'SH' + fernet.encrypt(str(online_users_lst).encode())


def handle_show_groups(req_parameters, **kwargs):
    # print(req_parameters)
    master_key = kwargs['master_key']
    fernet = Fernet(master_key)
    groups = []
    for group_username in state.state['groups']:
        if state.state['groups'][group_username]['admin'] == req_parameters or req_parameters in state.state['groups'][group_username]['members']:
            groups.append(group_username)
    # print('gpssssss', groups)
    return b'SG' + fernet.encrypt(str(groups).encode())   



def handle_logout(username, **kwargs):
    master_key = kwargs['master_key']
    fernet = Fernet(master_key)
    if username not in state.state['users']:
        return b'OU' + fernet.encrypt(b'USERNAME_DOES_NOT_EXISTS'.encode())
    state.state['users']['status'] = False
    return b'OU' + fernet.encrypt('LOGOUT_SUCCESSFULLY'.encode())


def handle_send_message(req_params, **kwargs):
    thread_pool = kwargs['thread_pool']
    print(req_params)
    sender_username, receiver_username, _, _, _ = req_params.split('**')
    if receiver_username not in state.state['users']:
        return b'UNF', thread_pool.pool.get(sender_username)
    master_key = state.state['users'][receiver_username]['master_key'].encode()
    fernet = Fernet(master_key)
    return b'LO' + fernet.encrypt(req_params.encode()), thread_pool.pool.get(receiver_username)


def handle_create_group(req_params, **kwargs):
    group_username, admin_username = req_params.split('|')
    master_key = kwargs['master_key']
    fernet = Fernet(master_key)
    if group_username in state.state['groups']:
        return b'CG' + fernet.encrypt(b'GROUPNAME_IS_NOT_UNIQUE')
    else:
        group_key = Fernet.generate_key()
        state.state['groups'][group_username] = {
            # 'session_key': group_key.decode(),
            'admin': admin_username,
            'members': [admin_username]
        }
        state.save_data()
        return b'CG' + fernet.encrypt(group_key)


def handle_group_users(req_parameters, **kwargs):
    group_username = req_parameters.split('|')[0]
    # print(group_username)
    master_key = kwargs['master_key']
    fernet = Fernet(master_key)
    if group_username not in state.state['groups']:
        return b'GU' + fernet.encrypt(b'GROUP_DOES_NOT_EXIST')
    else:
        return b'GU' + fernet.encrypt(str(state.state['groups'][group_username]['members']).encode())


def handle_add_to_group(req_params, **kwargs):
    username, group_username, new_member = req_params.split('|')
    if username != state.state['groups'][group_username]['admin']:
        return b'PD', None
    elif new_member not in state.state['users']:
        return b'ANF', None
    master_key = state.state['users'][new_member]['master_key'].encode()
    fernet = Fernet(master_key)
    thread_pool = kwargs['thread_pool']
    state.state['groups'][group_username]['members'].append(new_member)
    state.save_data()
    return b'AG' + fernet.encrypt(req_params.encode()), thread_pool.pool.get(new_member)


def handle_remove_from_group(req_params, **kwargs):
    username, group_username, remove_member = req_params.split('|')
    print(username, state.state['groups'][group_username]['admin'])
    if username != state.state['groups'][group_username]['admin']:
        return b'PD', None
    elif remove_member not in state.state['users'] or remove_member not in state.state['groups'][group_username]['members']:
        return b'RNF', None
    master_key = state.state['users'][remove_member]['master_key'].encode()
    fernet = Fernet(master_key)
    thread_pool = kwargs['thread_pool']
    state.state['groups'][group_username]['members'].remove(remove_member)
    state.save_data()
    return b'RG' + fernet.encrypt(req_params.encode()), thread_pool.pool.get(remove_member)



def handle_refresh_key(req_params, **kwargs):
    """
    This method set a shared key between two peers A, B. It sends A's parameters to B, receive
    B's parameters and finally send them back to A.
    :param req_params: client_username|peer|nonce|public_key
    :param kwargs: master_key
    :return: B's parameters to be sent to A
    """
    username, peer, nonce, public_key, parameters = req_params.split('|')
    if peer not in state.state['users']:
        return
    peer_master_key = state.state['users'][peer]['master_key'].encode()
    fernet = Fernet(peer_master_key)
    enc_request = b'NK' + fernet.encrypt(req_params.encode())

    # Send to B
    peer_connection = kwargs['peer_connection']
    print('refresh_key(peer, client_state)', enc_request)
    peer_connection.send(enc_request)


def handle_backward_key(req_params, **kwargs):
    username, peer, nonce, public_key, parameters = req_params.split('|')
    # Send back to A
    client_master_key = state.state['users'][username]['master_key'].encode()
    new_fernet = Fernet(client_master_key)

    sender_connection = kwargs['sender_connection']  # Sender = A
    response = b'SK' + new_fernet.encrypt(req_params.encode())
    sender_connection.send(response)
