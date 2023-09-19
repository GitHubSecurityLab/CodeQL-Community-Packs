from flask import Flask, request, abort

app = Flask(__name__)


class Users(object):
    uid: int
    username: str
    password: str

    def set(self, key: str, vaule: str):
        # codeql: py/mass-assignment
        self.__setattr__(key, vaule)


@app.route("/test1")
def test1():
    # Test 1: Simple test case
    i = request.args.get("i")
    user = Users()
    
    # codeql: py/mass-assignment
    setattr(user, request.args.get("k"), request.args.get("v"))
    
    # codeql: py/mass-assignment
    user.__setattr__(request.args.get("k"), request.args.get("v"))
    
    # Issue in the `set()` function
    user.set(request.args.get("k"), request.args.get("v"))

    # false-positive: variable isn't user controlled
    setattr(user, "uid", request.args.get("uid"))
    # same as: user.uid = i
    
    # false-positive: variable isn't user controlled
    user.__setattr__("uid", request.args.get("uid"))
    # same as: user.uid = i
    
    return f"<h1>Test 3</h1>"


@app.route("/test3")
def test3():
    user = Users()
    # Test 2:
    # remote-flow: requrst.args
    for param_name, param_vaule in request.args.items():
        # codeql: py/mass-assignment
        setattr(user, param_name, param_vaule)
    
    return f"<h1>Test 3</h1>"


@app.route("/test4")
def test4():
    # Test 3:
    if request.method == "PUT":
        if not request.json:
                abort(400)

        user_data = request.json
        user = Users()

        # remote-flow: requrst.args
        for item in user_data:
            # codeql: py/mass-assignment
            setattr(user, item, request.json[item])

    return f"<h1>Test 4</h1>"
