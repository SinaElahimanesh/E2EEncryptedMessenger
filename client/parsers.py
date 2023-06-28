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

def parse_send_message(em):
    rest, req_type = em.split('###')
    rest = rest.split()
    message = rest[1]
    receiver = rest[3]
    return message, receiver


def parse_login(em):
    rest, req_type = em.split('###')
    username, password = rest.split()[1:]
    return username, password


def parse_send_message(em, sender_username):
    rest, req_type = em.split('###')
    message, receiver_username = rest.split()[2:]
    return sender_username, receiver_username, message