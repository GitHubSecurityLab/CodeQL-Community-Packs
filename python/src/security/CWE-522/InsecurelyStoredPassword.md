# Python insecurely stored password
Storing passwords in plain text or in a reversible format is insecure. They can be recovered by either reading them straight out (in the case of plain text), or by reversing the storage method. Trivial encodings such as Base64 or hex encoding are not sufficient. Even encryption is not appropriate for storing passwords, since it can be reversed if the encryption key is stolen along with the passwords.


## Recommendation
Use strong, non-reversible cryptographic hashing to protect stored passwords. With Python, it is common to use Werkzeug's `generate_password_hash` function, but Flask-BCrypt and Flask-Argon2 are more modern and give you control over the number of "rounds" of hashing (repeated hashing to make reversing the hashing harder). You should ensure that you not only use such a function, but also use it securely. Make sure that the hashing function used is sufficiently strong (e.g. SHA-512) and that you use a per-password salt (which Werkzeug, BCrypt and Argon2 all do).


## Example
In this insecure snippet of Python, a password is stored with no hashing:

```python

from flask import Flask, request
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    __tablename__ = 'insecure_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80))

```
In this example, the password is hashed before it is stored:

```python

from flask import Flask, request
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

app = Flask(__name__)
db = SQLAlchemy(app)

class SecureUser(db.Model, UserMixin):
    __tablename__ = 'secure_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80))

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password, method="pbkdf2:sha512")

```

## References
* [werkzeug.generate_password_hash](https://tedboy.github.io/flask/generated/werkzeug.generate_password_hash.html)
* Common Weakness Enumeration: [CWE-256](https://cwe.mitre.org/data/definitions/256.html).
* Common Weakness Enumeration: [CWE-257](https://cwe.mitre.org/data/definitions/257.html).
* Common Weakness Enumeration: [CWE-522](https://cwe.mitre.org/data/definitions/522.html).
