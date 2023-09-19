from flask import Flask, request, render_template

app = Flask(__name__)

@app.route('/')
def index():
    # this is fine, no dynamic content
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    # this is not fine, dynamic content
    return render_template('login.html', username=username)

if __name__ == '__main__':
    app.run()
