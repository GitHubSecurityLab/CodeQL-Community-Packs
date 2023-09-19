
import os
from flask import Flask


def application1():
    app = Flask(__name__)
    # SECURITY WARNING: Hardcoded secret key
    app.secret_key = "ABCDEFG"

    app.run()


def application2():
    random_name = "HIJKLMN"
    app = Flask(__name__)
    # SECURITY WARNING: Hardcoded secret key
    app.secret_key = random_name

    app.run()


def application3():
    app = Flask(__name__)
    # SECURITY WARNING: Hardcoded secret key
    app.config['SECRET_KEY'] = "OPQRSTU"
    app.config['TESTING'] = True

    app.run()


def application4():
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        # SECURITY WARNING: Hardcoded secret key
        SECRET_KEY="WXYZ"
    )

    app.run()


def application5():
    app = Flask(__name__)
    # SECURITY WARNING: Hardcoded secret key
    # settings file contains secrets
    app.config.from_object('hardcoded.flask_settings')

    app.run()


def safeApplication1():
    app = Flask(__name__)
    # SAFE
    app.secret_key = os.environ.get('SECRET_KEY')

    app.run()


if __name__ == "__main__":
    application1()
    application2()
    application3()
    application4()
    application5()

    safeApplication1()
