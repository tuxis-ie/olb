# all the imports
from __future__ import with_statement
from contextlib import closing
import sqlite3
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash
import os.path
from bcrypt import hashpw, gensalt

# configuration
DATABASE = '/tmp/olb.db'
DEBUG = True
SECRET_KEY = 'obUG0QAauhoPQWIz5eCS102KfsDM3rOe/bxtNDtoA0M='
USERNAME = 'admin'
PASSWORD = 'default'

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)

app.config.from_envvar('FLASKR_SETTINGS', silent=True)

def connect_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.cursor().execute("INSERT INTO users (username, realname, password, email) VALUES (?, ?, ?, ?)", ['admin', 'Tuxis Internet Engineering', hashpw('koekje123', gensalt()), 'support@tuxis.nl'])
        db.commit()

if os.path.isfile(app.config['DATABASE']) == False:
    init_db()

def add_user():
    u = request.form['username']
    p = request.form['password']
    r = request.form['realname']
    e = request.form['email']

    if g.db.cursor().execute("INSERT INTO users (username, realname, password, email) \
        VALUES (?, ?, ?, ?)", [u, r, hashpw(p, gensalt()), e]):
        return True

    return False

def get_users():
    q = g.db.execute('SELECT * FROM users')
    return q.fetchall()

@app.before_request
def before_request():
    g.db = connect_db()

@app.teardown_request
def teardown_request(exception):
    g.db.close()

@app.route('/')
def show_main():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    return render_template('show_main.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']

        q = g.db.execute('SELECT password FROM users WHERE username = ?', [ u ])
        r = q.fetchone()
        if hashpw(p, r[0]) == r[0]:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('show_main'))

        error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/users', methods=['GET', 'POST'])
def users():
    error = None
    if request.method == 'POST':
        if add_user() == False:
            flash('There was an issue while adding the user')

    users = get_users()
    return render_template('users.html', users=users)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()

