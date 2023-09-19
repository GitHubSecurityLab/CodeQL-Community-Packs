
class Config(object):
    DEBUG = False
    TESTING = False


class ProductionConfig(Config):
    DATABASE_URI = 'mysql://user@localhost/foo'
    # SECURITY WARNING: Hardcoded secret key
    SECRET_TOKEN = "ThisIsASecretToken"


class DevelopmentConfig(Config):
    DATABASE_URI = "sqlite:////tmp/foo.db"


class TestingConfig(Config):
    DATABASE_URI = 'sqlite:///:memory:'
    DEBUG = True

    SECRET_TOKEN = "ThisIsATestToken"
