
import psycopg2

# input
username = input("Username:")

connection = psycopg2.connect(
    user="sysadmin",
    password="pynative@#29",
    host="127.0.0.1",
    port="5432",
    database="postgres_db"
)
cursor = connection.cursor()

# test 1 - Format string
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)

# test 2 - str.format()
query = "SELECT * FROM users WHERE username = '{}'".format(username)
cursor.execute(query)

# test 3 - %s
query = "SELECT * FROM users WHERE username = %s" % username
cursor.execute(query)


# test 4 - string + string
query = "SELECT * FROM users WHERE username = " + username
cursor.execute(query)
