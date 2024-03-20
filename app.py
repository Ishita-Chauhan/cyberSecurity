from flask import Flask, render_template, request, redirect, url_for, session
import bcrypt

app = Flask(__name__, template_folder='templates')
app.secret_key = '123456'

users = {}

@app.route('/')
def index():
    if 'username' in session:
        return f'Logged in as {session["username"]}<br><a href="/logout">Logout</a>'
    return 'You are not logged in<br><a href="/login">Login</a>'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store the username and hashed password in the users dictionary
        users[username] = hashed_password

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users and bcrypt.checkpw(password.encode('utf-8'), users[username]):
            session['username'] = username
            return redirect(url_for('index'))

        return 'Invalid username/password combination'

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
