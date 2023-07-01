import rsa

from client.functions import __generate_rsa_key


def parse_create_account(em):
    rest, req_type = em.split('###')
    username, password = rest.split()[2:]
    public = __generate_rsa_key(username, password)
    return username, password, public

def parse_create_group(em):
    rest, req_type = em.split('###')
    group_name = rest.split()[2]
    return group_name

def parse_create_group(em):
    rest, req_type = em.split('###')
    group_name = rest.split()[2]
    return group_name

# def parse_send_message(em):
#     rest, req_type = em.split('###')
#     rest = rest.split()
#     message = rest[1]
#     receiver = rest[3]
#     print(em, message, receiver)
#     return message, receiver


def parse_login(em):
    rest, req_type = em.split('###')
    username, password = rest.split()[1:]
    return username, password


def parse_send_message(em, sender_username):
    # rest, req_type = em.split('###')
    # message, receiver_username = rest.split()[2:]
    rest, req_type = em.split('###')
    rest = rest.split()
    message = rest[1]
    receiver = rest[3]
    return receiver, message
    # return sender_username, receiver_username, message


def parse_send_group_message(em):
    rest, req_type = em.split('###')
    rest = rest.split()
    message = rest[2]
    group = rest[4]
    return group, message


def parse_add_to_group(em):
    rest, req_type = em.split('###')
    rest = rest.split()
    new_member = rest[1]
    group_username = rest[3]
    return new_member, group_username


def parse_remove_from_group(em):
    rest, req_type = em.split('###')
    rest = rest.split()
    remove_username = rest[1]
    group_username = rest[3]
    return remove_username, group_username

