from argparse import ArgumentParser

# Inputs
parser = ArgumentParser(__name__)
parser.add_argument("-k")
parser.add_argument("-v")

arguments = parser.parse_args()


class Users(object):
    uid: int
    username: str
    password: str

    def set(self, key: str, vaule: str):
        # codeql: py/mass-assignment
        self.__setattr__(key, vaule)


user = Users()

# codeql: py/mass-assignment
setattr(user, arguments.k, arguments.v)

# codeql: py/mass-assignment
user.__setattr__(arguments.k, arguments.v)

# Issue in the `set()` function
user.set(arguments.k, arguments.v)

# false-positive: variable isn't user controlled
setattr(user, "uid", arguments.v)
# same as: user.uid = i

# false-positive: variable isn't user controlled
user.__setattr__("uid", arguments.v)
# same as: user.uid = i
