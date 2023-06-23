import rsa

from client.functions import __generate_rsa_key


def parse_create_account(em):
    rest, req_type = em.split('###')
    username, password = rest.split()[2:]
    public = __generate_rsa_key(username, password)
    return username, password, public
