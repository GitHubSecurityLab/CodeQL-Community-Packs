import os
import random
import uuid

# os module
os.getrandom(10)

# random module
random.seed("8")

random.random()
random.randrange(0, 10)
random.randint(0, 10)

random.randbytes(10)

# uuid module
uuid.uuid1()
uuid.uuid3(uuid.NAMESPACE_DNS, 'python.org')
uuid.uuid4()
uuid.uuid5(uuid.NAMESPACE_DNS, 'python.org')
