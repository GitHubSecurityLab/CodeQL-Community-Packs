import os
import django

# const key
SECRET_KEY = "SuperSecretKey"
# const default key
SECRET_KEY = os.environ.get("SECRET_KEY", "secret")
# False Positive, key from env
SECRET_KEY = os.environ.get("SECRET_KEY")


RANDOM_STRING = "SuperRandomString"
SECRET_KEY = RANDOM_STRING
