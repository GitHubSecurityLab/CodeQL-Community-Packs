import os

password = os.environ.get("SECRET_TOKEN")

# Flask
from flask import Flask

app = Flask(__name__)

app.secret_key = "SecretKey1"
app.config["SECRET_KEY"] = "SecretKey2"
app.config.update(SECRET_KEY="SecretKey3")


# Django
SECRET_KEY = "SuperSecretKey"  # False Positive, not a settings file


# Requests
from requests.auth import HTTPBasicAuth

auth = HTTPBasicAuth("user", "mysecretpassword")


# MySQL
from mysql.connector import connect

conn = connect(user="user", password="mysecretpassword")

# Asyncpg
from asyncpg import connect
from asyncpg.connection import Connection

asyncpg_conn1 = await connect(user="user", password="asyncpg_secret1")
asyncpg_conn2 = Connection(user="user", password="asyncpg_secret2")

# JWT
import jwt

jwt_encoded = jwt.encode({"some": "payload"}, "jwt_secret1", algorithm="HS256")
jwt_decode = jwt.decode(jwt_encoded, "jwt_secret2", algorithm="HS256")


# Redis
import aioredis

redis = await aioredis.create_redis_pool("redis://localhost", password="ReDiSsEcRet1")

w = "ReDiSsEcRet2"
redis = await aioredis.create_redis_pool("redis://localhost", password=w)


# PyOtp
import pyotp

totp = pyotp.TOTP("base32secret3232")

p = "base32secret3232"
totp2 = pyotp.TOTP(p)

p = os.environ.get("OPT_KEY")
totp2 = pyotp.TOTP(p)


# Bota3
import boto3

s3 = boto3.resource(
    "s3",
    aws_access_key_id="YOUR-ACCESSKEYID",
    aws_secret_access_key="YOUR-SECRETACCESSKEY",
    aws_session_token="YOUR-SESSION-TOKEN",
)