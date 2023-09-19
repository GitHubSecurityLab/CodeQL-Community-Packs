import os

i = input("Enter command: ")

# direct input
exec(i)

# Env variable
e1 = os.environ["LOCAL_DATA"]
exec(e1)

e2 = os.environ.get("LOCAL_DATA")
exec(e2)
