# all the imports
from __future__ import with_statement
from contextlib import closing
import sqlite3
import json
from datetime import datetime
import re
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash, jsonify
import os
from bcrypt import hashpw, gensalt
import ipaddr
import shutil

# configuration
CONFIGREPO = "config"
DATABASE = CONFIGREPO+'/olb.db'
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

if os.path.isdir(app.config['CONFIGREPO']) == False:
    os.mkdir(app.config['CONFIGREPO'])

if os.path.isfile(app.config['DATABASE']) == False:
    init_db()

@app.template_filter('ip_convert')
def ip_convert(ip):
    if ip.startswith('4-'):
        return str(ipaddr.IPv4Address(int(ip[2:])))
    elif ip.startswith('6-'):
        return "[%s]" % str(ipaddr.IPv6Address(long(ip[2:])))
    else:
        if re.match(".*:.*", ip):
            return str('6-')+str(int(ipaddr.IPv6Address(ip)))
        else:
            return str('4-')+str(int(ipaddr.IPv4Address(ip)))

def check_if_admin():
    return session['username'] == 'admin'

class pException(Exception):
    def __init__(self, mismatch):
        Exception.__init__(self, mismatch)

def adminonly(f):
    def wrapper(*args, **kwargs):
        if not check_if_admin():
            raise pException('Permission denied')
        return f(*args, **kwargs)
    return wrapper

@adminonly
def do_commit(tag, msg):
    try:
        cdir = os.path.join(app.config['CONFIGREPO'], tag)
        os.mkdir(cdir)
        l = file(os.path.join(cdir, 'message'), 'w')
        l.write(msg)
        l.close()
        shutil.copy2(app.config['DATABASE'], os.path.join(cdir, 'olb.db'))
        os.chmod(os.path.join(cdir, 'olb.db'), 0400)
    except Exception, e:
        raise pException(e)

@adminonly
def do_config_export(tag):
    try:
        cdir = os.path.join(app.config['CONFIGREPO'], tag)
        edb = sqlite3.connect(os.path.join(cdir, 'olb.db'))
        edb.row_factory = sqlite3.Row
        edb.cursor().execute("PRAGMA foreign_keys = ON");
    except Exception, e:
        raise pException("While trying to open commited db: %s" % (e))

    naddrs = ['mark@tuxis.nl']

    vips = []
    q = edb.execute('SELECT v.*, p.id as pid, pt.typeconf FROM vips v, pools p, pooltypes pt WHERE v.pool = p.id AND p.pooltype = pt.id ORDER BY ip')
    for v in q.fetchall():
        vip = {}
        vip['ip'] = v['ip']
        vip['port'] = v['port']
        vip['typeconf'] = v['typeconf']
        vip['nodes'] = []
        pool = {}
        pq = edb.execute('SELECT n.ip, n.port FROM nodes n, poolnodes pn WHERE n.id = pn.node AND pn.id = ?', [v['pid']])
        for n in pq.fetchall():
            node = {}
            node['ip'] = n['ip']
            node['port'] = n['port']
            vip['nodes'].append(node)
        vips.append(vip)

    c = file(os.path.join('/tmp', 'keepalived.conf'), 'w')
    c.write(render_template('keepalived/keepalived.conf', naddrs=naddrs, vips=vips))
    c.close()

@adminonly
def get_commits():
    commits = {}
    for root, dirs, files in os.walk(app.config['CONFIGREPO']):
        if len(dirs) == 0:
            ts = os.path.basename(root)
            commits[ts] = {}
            if os.path.isfile(os.path.join(root, 'message')):
                with open(os.path.join(root, 'message')) as cmsg:
                    commits[ts]['message'] = cmsg.read()
                    commits[ts]['timestamp'] = ts

    ret = []
    for ts in sorted(commits, reverse=True):
        ret.append(commits[ts])

    return ret

@adminonly
def add_user():
    u = request.form['username']
    p = request.form['password']
    r = request.form['realname']
    e = request.form['email']

    try:
        g.db.execute("INSERT INTO users (username, realname, password, email) \
            VALUES (?, ?, ?, ?)", [u, r, hashpw(p, gensalt()), e])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def del_user():
    uid = request.form['uid']
    try:
        g.db.execute("DELETE FROM users WHERE id = ?", [ uid ])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

def get_user(name=False, uid=False):
    if name != False:
        q = g.db.execute('SELECT * FROM users WHERE username = ?', [ name ])
    if uid != False:
        q = g.db.execute('SELECT * FROM users WHERE id = ?', [ uid ])
    return q.fetchone()

@adminonly
def get_users():
    q = g.db.execute('SELECT * FROM users ORDER BY username')
    return q.fetchall()

@adminonly
def add_node():
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
        raise pException(e)

@adminonly
def del_node():
    nodeid = request.form['nodeid']
    try:
        g.db.execute("DELETE FROM nodes WHERE id = ?", [nodeid])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

def get_nodes():
    o = session['oid']
    q = g.db.execute('SELECT * FROM nodes WHERE owner = ? ORDER BY ip', [ o ])

    return q.fetchall()

def get_pool_types():
    q = g.db.execute('SELECT * FROM pooltypes');
    return q.fetchall()

def add_pool_node(nid, pid, owner):
    if not check_if_admin():
        raise pException("Permission denied")
    try:
        g.db.execute('INSERT INTO poolnodes (node, pool, owner) \
            VALUES (?, ?, ?)', [ nid, pid, owner ])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def del_pool_node():
    pnodeid = request.form.get('pnid')
    try:
        g.db.execute("DELETE FROM poolnodes WHERE id = ?", [pnodeid])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def add_pool():
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
            add_pool_node(n, pid, oid)
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)
 
@adminonly
def del_pool():
    poolid = request.form['poolid']
    try:
        g.db.execute("DELETE FROM pools WHERE id = ?", [poolid])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

def get_pools():
    o = session['oid']
    q = g.db.execute('SELECT p.*, pt.typename FROM pools p, pooltypes pt WHERE p.owner = ? AND p.pooltype = pt.id ORDER BY poolname', [ o ])

    return q.fetchall()

def get_pool_nodes(poolid):
    o = session['oid']
    q = g.db.execute('SELECT p.*, n.*, pn.id as nodeid FROM pools p, nodes n, poolnodes pn \
        WHERE p.owner = ? and n.id = pn.node and pn.pool = p.id AND p.id = ? ORDER BY n.ip', [ o, poolid ])

    return q.fetchall()

def get_vips():
    o = session['oid']
    q = g.db.execute('SELECT v.*, p.poolname FROM vips v, pools p WHERE v.owner = ? AND v.pool = p.id ORDER BY ip', [ o ])

    return q.fetchall()

@adminonly
def add_vip():
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
        raise pException(e)

@adminonly
def del_vip():
    vipid = request.form['vipid']
    try:
        g.db.execute("DELETE FROM vips WHERE id = ?", [vipid])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

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
@adminonly
def users():
    error = None
    if request.method == 'POST':
        a = request.form.get('action')
        if a == "add":
            u = request.form.get('username')
            try:
                add_user()
                return jsonify(message="Added user %s!" % ( u ))
            except Exception, e:
                return jsonify(error="Could not add user %s (%s)" % ( u, e ))
        elif a == "delete":
            uid = request.form.get('uid')
            u = get_user(uid=uid)['username']
            try:
                del_user()
                return jsonify(message="User %s deleted (and all it's settings)!" % ( u ))
            except Exception, e:
                return jsonify(error="Could not delete user %s (%s)" % ( u, e ))

    users = get_users()
    return render_template('users.html', users=users)

@app.route('/nodes', methods=['GET', 'POST'])
def nodes():
    error = None
    if request.method == 'POST':
        a = request.form.get('action')
        if a == "add":
            try:
                add_node()
                return jsonify(message="Node added")
            except Exception, e:
                return jsonify(error="Cannot add node (%s)" % (e))
        elif a == "delete":
            try:
                del_node()
                return jsonify(message="Node deleted")
            except Exception, e:
                return jsonify(error="Cannot delete node (%s)" % (e))

    nodes = get_nodes()
    return render_template('nodes.html', nodes=nodes)

@app.route('/pools', methods=['GET', 'POST'])
def pools():
    error = None
    if request.method == 'POST':
        a = request.form.get('action')
        if a == "add":
            try:
                add_pool()
                return jsonify(message="Pool added")
            except Exception, e:
                return jsonify(error="Cannot add pool (%s)" % (e))
        elif a == "delete":
            try:
                del_pool()
                return jsonify(message="Pool deleted")
            except Exception, e:
                return jsonify(error="Cannot delete pool (%s)" % (e))
        elif a == "add_pool_node":
            try:
                nid = request.form.get('nodeid')
                pid = request.form.get('poolid')
                owner = session['oid']
                add_pool_node(nid, pid, owner)
                return jsonify(message="Node added to pool")
            except Exception, e:
                return jsonify(error="Could not add node to pool (%s)" % (e))
        elif a == "delete_pn":
            try:
                del_pool_node()
                return jsonify(message="Node deleted from pool")
            except Exception, e:
                return jsonify(error="Could not delete node from pool (%s)" % (e))

    dpools = get_pools()
    nodes = get_nodes()
    pooltypes = get_pool_types()
    tpools = []

    for pool in dpools:
        rpool = dict(pool)
        poolnodes = get_pool_nodes(pool['id'])
        rpool['nodes'] = poolnodes
        rpool['anodes'] = nodes
        tpools.append(rpool)

    
    return render_template('pools.html', pools=tpools, nodes=nodes, pooltypes=pooltypes)

@app.route('/vips', methods=['GET', 'POST'])
def vips():
    error = None
    if request.method == 'POST':
        a = request.form.get('action')
        if a == "add":
            try:
                add_vip()
                return jsonify(message="Vip added")
            except Exception, e:
                return jsonify(error="Cannot add vip (%s)" % (e))
        elif a == "delete":
            try:
                del_vip()
                return jsonify(message="Vip deleted")
            except Exception, e:
                return jsonify(error="Cannot delete vip (%s)" % (e))

    pools = get_pools()
    vips  = get_vips()
    return render_template('vips.html', pools=pools, vips=vips)

@app.route('/commit', methods=['GET', 'POST'])
def commit():
    if request.method == 'POST':
        cmsg = ""
        try:
            cmsg = request.form.get('cmsg')
        except:
            cmsg = "new commit"
    
        now = datetime.now()
        tag = now.strftime("%Y%m%d%H%M%S")
        try:
            do_commit(tag, cmsg)
            do_config_export(tag)
            return jsonify(message="Commited %s as %s" % (cmsg, tag))
        except Exception, e:
            return jsonify(error="Could not commit: %s" % (e))

    commits = get_commits()

    return render_template('commit.html', history=commits)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    return render_template('settings.html', settings=settings)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='::')

