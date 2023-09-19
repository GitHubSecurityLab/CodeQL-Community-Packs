
from requests import get
from requests.auth import HTTPBasicAuth


def test1():
    r = get('https://api.github.com/user', auth=('user', 'mysecretpassword'))

    return r.text


def test2():
    r = get('https://api.github.com/user', auth=HTTPBasicAuth('user', 'mysecretpassword'))

    return r.text
