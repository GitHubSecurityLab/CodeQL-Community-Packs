
import os
import pickle
import shelve
import marshal


class Evil(object):
    def __reduce__(self):
        return (os.system, ('ls',))


# Load / unload pickle
my_data = pickle.dumps(Evil())
p = pickle.loads(my_data)


# Check local file loading sinks (built into CodeQL now)
# codeql/python/ql/lib/semmle/python/frameworks/Stdlib.qll
with open("cache/obj") as handle:
    p2 = pickle.load(handle)

with open("cache/obj") as handle:
    m2 = marshal.load(handle)

with open("cache/obj") as handle:
    p2 = shelve.open(handle)
