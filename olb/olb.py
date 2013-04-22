# all the imports
from __future__ import with_statement
from contextlib import closing
import sqlite3
import json
import re
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash
import os.path
from bcrypt import hashpw, gensalt
import ipaddr

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
    conn.cursor().execute("PRAGMA foreign_keys = ON");
    return conn

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.cursor().execute("INSERT INTO users (username, realname, password, email) VALUES (?, ?, ?, ?)", ['admin', 'Tuxis Internet Engineering', hashpw('admin', gensalt()), 'support@tuxis.nl'])
        db.commit()

if os.path.isfile(app.config['DATABASE']) == False:
    init_db()

@app.template_filter('ip_convert')
def ip_convert(ip):
    if re.match("^4-", ip):
        return str(ipaddr.IPv4Address(int(ip[2:])))
    elif re.match("^6-", ip):
        return "[%s]" % str(ipaddr.IPv6Address(long(ip[2:])))
    else:
        if re.match(".*:.*", ip):
            return str('6-')+str(int(ipaddr.IPv6Address(ip)))
        else:
            return str('4-')+str(int(ipaddr.IPv4Address(ip)))

def check_if_admin():
    try:
        if session['username'] != 'admin':
            return False
        return True
    except:
        return False

def add_user():
    if check_if_admin() == False:
        return False
    u = request.form['username']
    p = request.form['password']
    r = request.form['realname']
    e = request.form['email']

    try:
        g.db.execute("INSERT INTO users (username, realname, password, email) \
            VALUES (?, ?, ?, ?)", [u, r, hashpw(p, gensalt()), e])
        g.db.commit()
        return True
    except Exception:
        return False

def del_user():
    if check_if_admin() == False:
        return False
    uid = request.form['uid']
    try:
        g.db.execute("DELETE FROM users WHERE id = ?", [ uid ])
        g.db.commit()
        return True
    except Exception:
        return False

def get_user(name=False, uid=False):
    if name != False:
        q = g.db.execute('SELECT * FROM users WHERE username = ?', [ name ])
    if uid != False:
        q = g.db.execute('SELECT * FROM users WHERE id = ?', [ uid ])
    return q.fetchone()

def get_users():
    if check_if_admin() == False:
        return False
    q = g.db.execute('SELECT * FROM users ORDER BY username')
    return q.fetchall()

def add_node():
    if check_if_admin() == False:
        return False
    d = request.form['description']
    i = request.form['ipaddress']
    p = request.form['port']
    o = session['oid']

    try:
        g.db.execute("INSERT INTO nodes (description, ip, port, owner) \
            VALUES (?, ?, ?, ?)", [d, ip_convert(i), p, o])
        g.db.commit()
        return True
    except Exception, e:
        print e
        return False

def get_nodes():
    o = session['oid']
    q = g.db.execute('SELECT * FROM nodes WHERE owner = ? ORDER BY ip', [ o ])

    return q.fetchall()

def check_node_owner(nid, owner):
    q = g.db.execute('SELECT * FROM nodes WHERE id = ? AND owner = ?', [ nid, owner ])
    if q.fetchone() != None:
        return True
    else:
        return False

def get_pool_types():
    q = g.db.execute('SELECT * FROM pooltypes');
    return q.fetchall()

def add_pool_node(nid, pid, owner):
    if check_if_admin() == False:
        return False
    q = g.db.execute('INSERT INTO poolnodes (node, pool, owner) \
        VALUES (?, ?, ?)', [ nid, pid, owner ])

def add_pool():
    if check_if_admin() == False:
        return False
    i = request.form['poolname']
    p = request.form['pooltype']
    m = request.form.getlist('members[]')
    oid = session['oid']

    # Do a member-ownership check
    try:
        q = g.db.execute("INSERT INTO pools (poolname, owner, pooltype) \
            VALUES (?, ?, ?)", [i, oid, p])
        pid = q.lastrowid
        for n in m:
            if check_node_owner(n, oid) == True:
                add_pool_node(n, pid, oid)
        g.db.commit()
        return True
    except Exception, e:
        print e
        return False

def get_pools():
    o = session['oid']
    q = g.db.execute('SELECT p.*, pt.typename FROM pools p, pooltypes pt WHERE p.owner = ? AND p.pooltype = pt.id ORDER BY poolname', [ o ])

    return q.fetchall()

def get_pool_nodes(poolid):
    o = session['oid']
    q = g.db.execute('SELECT p.*, n.* FROM pools p, nodes n, poolnodes pn \
        WHERE p.owner = ? and n.id = pn.node and pn.pool = p.id AND p.id = ? ORDER BY n.ip', [ o, poolid ])

    return q.fetchall()

def get_vips():
    o = session['oid']
    q = g.db.execute('SELECT v.*, p.poolname FROM vips v, pools p WHERE v.owner = ? AND v.pool = p.id ORDER BY ip', [ o ])

    return q.fetchall()

def add_vip():
    if check_if_admin() == False:
        return False
    i = request.form['ipaddress']
    p = request.form['port']
    pl = request.form['pool']
    o = session['oid']

    try:
        g.db.execute("INSERT INTO vips (ip, port, pool, owner) \
            VALUES (?, ?, ?, ?)", [ip_convert(i), p, pl, o])
        g.db.commit()
        return True
    except Exception, e:
        print e
        return False

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

    return render_template('layout.html')

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
            session['username']  = u
            session['oid'] = get_user(name=u)['id']
            flash('You were logged in')
            return redirect(url_for('show_main'))

        error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/users', methods=['GET', 'POST'])
def users():
    if check_if_admin() == False:
        return False
    error = None
    if request.method == 'POST':
        a = request.form.get('action')
        if a == "add":
            u = request.form.get('username')
            if add_user() == False:
                ret = {}
                ret['error'] = "Could not add user %s (does it already exist?)" % ( u )
                return json.dumps(ret)
            else:
                ret = {}
                ret['message'] = "Added user %s!" % ( u )
                return json.dumps(ret)
        elif a == "delete":
            uid = request.form.get('uid')
            u = get_user(uid=uid)['username']
            if del_user() == False:
                ret = {}
                ret['error'] = "Could not delete user %s" % ( u )
                return json.dumps(ret)
            else:
                ret = {}
                ret['message'] = "User %s deleted (and all it's settings)!" % ( u )
                return json.dumps(ret)

    users = get_users()
    return render_template('users.html', users=users)

@app.route('/nodes', methods=['GET', 'POST'])
def nodes():
    error = None
    if request.method == 'POST':
        if add_node() == False:
            ret = {}
            ret['error'] = "Cannot add node (does it already exist?)"
            return json.dumps(ret)

    nodes = get_nodes()
    return render_template('nodes.html', nodes=nodes)

@app.route('/pools', methods=['GET', 'POST'])
def pools():
    error = None
    if request.method == 'POST':
        if add_pool() == False:
            ret = {}
            ret['error'] = "Cannot add pool (does it already exist?)"
            return json.dumps(ret)

    dpools = get_pools()
    tpools = []
    for pool in dpools:
        rpool = dict(pool)
        poolnodes = get_pool_nodes(pool['id'])
        rpool['nodes'] = poolnodes
        tpools.append(rpool)

    nodes = get_nodes()
    pooltypes = get_pool_types()
    return render_template('pools.html', pools=tpools, nodes=nodes, pooltypes=pooltypes)

@app.route('/vips', methods=['GET', 'POST'])
def vips():
    error = None
    if request.method == 'POST':
        if add_vip() == False:
            ret = {}
            ret['error'] = "Cannot add vip (does it already exist?)"
            return json.dumps(ret)

    pools = get_pools()
    vips  = get_vips()
    return render_template('vips.html', pools=pools, vips=vips)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run()

