# all the imports
from __future__ import with_statement
from contextlib import closing
from functools import wraps
import sqlite3
import uuid
import json
from datetime import datetime
from socket import getfqdn
import re
from flask import Flask, request, session, g, redirect, url_for, \
     abort, render_template, flash, jsonify
import os
from bcrypt import hashpw, gensalt
import ipaddr
import shutil
import pycurl

from werkzeug.contrib.securecookie import SecureCookie

class JSONSecureCookie(SecureCookie):
    serialization_method = json

# configuration
CONFIGREPO = "config"
DATABASE = CONFIGREPO+'/olb.db'
SECRET = CONFIGREPO+'/secret'
RRDDIR = "rrd"
DEBUG = True
USERNAME = 'admin'
PASSWORD = 'default'

if os.path.isdir(CONFIGREPO) == False:
        os.mkdir(CONFIGREPO)

if os.path.isfile(SECRET) == False:
    f = open(SECRET, 'w')
    f.write(os.urandom(64))
    f.close()

SECRET_KEY=open(SECRET).read()

requiredsettings = [ 'naddr', 'faddr', 'maxcommits', 'synciface' ]

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)

app.config.from_envvar('FLASKR_SETTINGS', silent=True)

def connect_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    conn.cursor().execute("PRAGMA foreign_keys = ON");
    return conn

def find_ifaces():
    with open('/proc/net/dev') as p:
        for l in p.readlines():
            fields = l.split(':')
            if re.match("\s+eth[0-9]+", fields[0]):
                with closing(connect_db()) as db:
                    db.execute("INSERT INTO interfaces (iname) \
                        VALUES (?)", ["".join(fields[0].split())])
                    db.commit()

def init_db():
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.cursor().execute("INSERT INTO users (username, realname, password, email) VALUES (?, ?, ?, ?)", ['admin', 'Tuxis Internet Engineering', hashpw('admin', gensalt()), 'support@tuxis.nl'])
        db.commit()

if os.path.isfile(app.config['DATABASE']) == False:
    init_db()
    find_ifaces()

@app.template_filter('ip_convert')
def ip_convert(ip):
    if ip.startswith('4-'):
        return str(ipaddr.IPv4Address(int(ip[2:])))
    elif ip.startswith('6-'):
        return str(ipaddr.IPv6Address(long(ip[2:])))
    else:
        if re.match(".*:.*", ip):
            return str('6-')+str(int(ipaddr.IPv6Address(ip)))
        else:
            return str('4-')+str(int(ipaddr.IPv4Address(ip)))

@app.context_processor
def inject_random():
    return dict(random=uuid.uuid1())

def check_if_admin():
    return session['username'] == 'admin'

def needlogin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper

class pException(Exception):
    def __init__(self, mismatch):
        Exception.__init__(self, mismatch)

def adminonly(f):
    def wrapper(*args, **kwargs):
        if not check_if_admin():
            raise pException('Permission denied')
        return f(*args, **kwargs)
    return wrapper

def checkinput(f, t=None):
    t = f if t is None else t
    validators = {}
    validators['username'] = {}
    validators['username']['error'] = "Invalid username"
    validators['username']['regexp'] = "^[a-z0-9][-_.a-z0-9]+$"
    validators['ipaddress'] = {}
    validators['ipaddress']['error'] = "Invalid IP address"
    validators['ipaddress']['regexp'] = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?)$"
    validators['port'] = {}
    validators['port']['error'] = "Invalid port"
    validators['port']['regexp'] = "^([0-5]?\d?\d?\d?\d|6[0-4]\d\d\d|65[0-4]\d\d|655[0-2]\d|6553[0-5])$"
    validators['any'] = {}
    validators['any']['error'] = "Invalid any"
    validators['any']['regexp'] = "^.*$"
    validators['iface'] = {}
    validators['iface']['error'] = "Invalid any"
    validators['iface']['regexp'] = "^eth[0-9]+$"
    validators['number'] = {}
    validators['number']['error'] = "Invalid number"
    validators['number']['regexp'] = "^[0-9]+$"
    validators['action'] = {}
    validators['action']['error'] = "Invalid action"
    validators['action']['regexp'] = "^(add(_pool_node|_iface|_vrrp)?|delete(_pn|_iface|_vrrp)?|ptchange|save_all|edit)$"
    validators['hostname'] = {}
    validators['hostname']['error'] = "Invalid hostname"
    validators['hostname']['regexp'] = "^([a-z0-9]([-_a-z0-9]*[-_a-z0-9])?\\.)+((a[cdefgilmnoqrstuwxz]|aero|arpa)|(b[abdefghijmnorstvwyz]|biz)|(c[acdfghiklmnorsuvxyz]|cat|com|coop)|d[ejkmoz]|(e[ceghrstu]|edu)|f[ijkmor]|(g[abdefghilmnpqrstuwy]|gov)|h[kmnrtu]|(i[delmnoqrst]|info|int)|(j[emop]|jobs)|k[eghimnprwyz]|l[abcikrstuvy]|(m[acdghklmnopqrstuvwxyz]|mil|mobi|museum)|(n[acefgilopruz]|name|net)|(om|org)|(p[aefghklmnrstwy]|pro)|qa|r[eouw]|s[abcdeghijklmnortvyz]|(t[cdfghjklmnoprtvwz]|travel)|u[agkmsyz]|v[aceginu]|w[fs]|y[etu]|z[amw])$"
    validators['email'] = {}
    validators['email']['error'] = "Invalid emailaddress"
    validators['email']['regexp'] = "^[a-zA-Z0-9_\.\-]+\@([a-zA-Z0-9\-]+\.)+[a-zA-Z0-9]{2,4}$"
    validators['moreemail'] = {}
    validators['moreemail']['error'] = "Invalid emailaddress"
    validators['moreemail']['regexp'] = "^([a-zA-Z0-9_\.\-]+\@([a-zA-Z0-9\-]+\.)+[a-zA-Z0-9]{2,4}(,\s*)?)+$"
    validators['faddr'] = validators['email']
    validators['naddr'] = validators['moreemail']
    validators['maxcommits'] = validators['number']
    validators['synciface'] = validators['number']
    validators['password'] = validators['any']

    try:
        if validators[t]['error'] != "":
            pass
    except Exception, e:
        raise pException("Unknown validator type")

    try:
        if f.endswith('[]'):
            v = request.form.getlist(f)
        else:
            v = request.form.get(f)
    except Exception, e:
        raise pException("Could not find this variable")

    if type(v) is list:
        for vv in v:
            if re.match(validators[t]['regexp'], vv) == None:
                raise pException("Validation of %s (%s)failed" % (f, vv))
        return v
    else:
        if re.match(validators[t]['regexp'], v) != None:
            return v
        else:
            raise pException("Validation of %s (%s) failed" % (f, v))

@adminonly
def do_commit(tag, msg):
    settings = get_settings()
    try:
        if settings['peer1'] != None and settings['peer2'] != None:
            if settings['peer1'] == getfqdn():
                commitpeer = settings['peer2']
            elif settings['peer2'] == getfqdn():
                commitpeer = settings['peer1']
            else:
                commitpeer = False
    except:
        pass

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

    if commitpeer != False:
        send_commit(commitpeer, tag, msg)

    try:
        cleanup_commits()
    except Exception, e:
        raise pException("While cleaning up commits: %s" % (e))

def send_commit(commitpeer, tag, msg):
    c = pycurl.Curl()
    c.setopt(c.COOKIEJAR, "/tmp/.olb.cookie");

    cdir = os.path.join(app.config['CONFIGREPO'], tag)

    password = checkinput("peerpw", 'any')

    fvalues = [
        ("cmsg", str(msg)),
        ("sender", str(getfqdn())),
        ("tag", str(tag)),
        ("commitfile", (c.FORM_FILE, os.path.join(cdir, 'olb.db'))),
        ("username", str("admin")),
        ("password", str(password))
    ]

    url = "http://%s/commit" % ( commitpeer )
    c.setopt(c.PORT, 5000)
    c.setopt(c.URL, str(url))
    c.setopt(c.HTTPPOST, fvalues)
    c.perform()
    c.close()

def recv_commit(tag, msg):
    try:
        cdir = os.path.join(app.config['CONFIGREPO'], tag)
        os.mkdir(cdir)
        l = file(os.path.join(cdir, 'message'), 'w')
        l.write(msg)
        l.close()
        dbfile = request.files['commitfile']
        dbfile.save(os.path.join(cdir, 'olb.db'))
        dbfile.save(os.path.join(app.config['CONFIGREPO'], 'olb.db'))
    except Exception, e:
        raise pException(e)

    try:
        cleanup_commits()
    except Exception, e:
        raise pException("While cleaning up commits: %s" % (e))

def remove_commit(tag):
    cdir = os.path.join(app.config['CONFIGREPO'], tag)
    try:
        os.chmod(os.path.join(cdir, 'olb.db'), 0600)
        os.remove(os.path.join(cdir, 'olb.db'))
    except:
        pass

    try:
        os.remove(os.path.join(cdir, 'message'))
    except:
        pass

    try:
        os.rmdir(cdir)
    except Exception, e:
        raise pException(e)
        
@adminonly
def cleanup_commits():
    settings = get_settings()
    commits  = get_commits()

    commits.reverse()

    ncommits = len(commits)
    if ncommits > settings['maxcommits']:
        tocleanup = int(ncommits)-int(settings['maxcommits'])
        counter = 0
        for c in commits:
            try:
                remove_commit(c['timestamp'])
            except Exception, e:
                raise pException("While removing %s" % (e))

            counter = counter+1
            if counter >= tocleanup:
                break

@adminonly
def do_config_export(tag):
    try:
        cdir = os.path.join(app.config['CONFIGREPO'], tag)
        edb = sqlite3.connect(os.path.join(cdir, 'olb.db'))
        edb.row_factory = sqlite3.Row
        edb.cursor().execute("PRAGMA foreign_keys = ON");
    except Exception, e:
        raise pException("While trying to open commited db: %s" % (e))

    vips = []
    vrrps = []
    q = edb.execute('SELECT v.*, p.id as pid, pt.typeconf, i.iname \
        FROM vips v, pools p, pooltypes pt, interfaces i \
        WHERE v.pool = p.id AND p.pooltype = pt.id AND i.id = v.interface \
        ORDER BY ip')
    for v in q.fetchall():
        vip = {}
        vip['ip'] = v['ip']
        vip['port'] = v['port']
        vip['typeconf'] = v['typeconf']
        vip['interface'] = v['iname']
        vip['nodes'] = []
        pool = {}
        pq = edb.execute('SELECT n.ip, n.port FROM nodes n, poolnodes pn WHERE n.id = pn.node AND pn.pool = ?', [v['pid']])
        for n in pq.fetchall():
            node = {}
            node['ip'] = n['ip']
            node['port'] = n['port']
            vip['nodes'].append(node)
        vips.append(vip)
        vrrps.append(vip)

    q = edb.execute('SELECT v.*, i.iname FROM vrrp v, interfaces i WHERE i.id = v.interface \
        ORDER BY address')
    for v in q.fetchall():
        vrrp = {}
        vrrp['ip'] = v['address']
        vrrp['interface'] = v['iname']
        vrrps.append(vrrp)

    settings = get_settings()
    settings['naddrs'] = settings['naddr'].split(',')
    c = file(os.path.join(cdir, 'keepalived.conf'), 'w')
    c.write(render_template('keepalived/keepalived.conf', settings=settings, vips=vips, vrrps=vrrps))
    c.close()

@adminonly
def get_commits():
    commits = []
    ret = []
    for root, dirs, files in os.walk(app.config['CONFIGREPO']):
        if len(dirs) == 0:
            ts = os.path.basename(root)
            commits.append(ts)
    
    for c in sorted(commits, reverse=True):
        cd = {}
        root = os.path.join(app.config['CONFIGREPO'], c)
        if os.path.isfile(os.path.join(root, 'message')):
            with open(os.path.join(root, 'message')) as cmsg:
                cd['message'] = cmsg.read()
                cd['timestamp'] = c
            ret.append(cd)

    return ret

@adminonly
def save_setting(key, val, kid = False):
    try:
        g.db.execute("REPLACE INTO settings (skey, sval) VALUES (?, ?)", [key, val])
        g.db.commit()
    except Exception, e:
        raise pException("While updating settings: %s", e)

@adminonly
def req_settings_set():
    for key in requiredsettings:
        q = g.db.execute("SELECT * FROM settings WHERE skey = ?", [key])
        if len(q.fetchall()) == 0:
            return False

    return True

@adminonly
def get_settings():
    ret = {}
    q = g.db.execute("SELECT * FROM settings")
    for r in q.fetchall():
        ret[r['skey']] = r['sval']

    ret['hostname'] = getfqdn()
    try:
        ret['peer1']
    except:
        ret['peer1'] = ret['hostname']

    try:
        ret['syncifacename'] = get_iface(ret['synciface'])['iname']
    except:
        pass

    return ret

@adminonly
def add_user():
    try:
        u = checkinput('username')
        p = checkinput('password', 'any')
        r = checkinput('realname', 'any')
        e = checkinput('email')
    except Exception, e:
        raise pException(e)


    try:
        g.db.execute("INSERT INTO users (username, realname, password, email) \
            VALUES (?, ?, ?, ?)", [u, r, hashpw(p, gensalt()), e])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def edit_user():
    try:
        u = checkinput('username')
        p = checkinput('password', 'any')
        r = checkinput('realname', 'any')
        e = checkinput('email')
    except Exception, e:
        raise pException(e)

    try:
        if p != "unchanged":
            g.db.execute("UPDATE users SET username = ?, realname = ?, password = ?, email = ? WHERE username = ?", [u, r, hashpw(p, gensalt()), e, u])
        else:
            g.db.execute("UPDATE users SET username = ?, realname = ?, email = ? WHERE username = ?", [u, r, e, u])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def del_user():
    try:
        uid = checkinput('uid', 'number')
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
    try:
        d = checkinput('description', 'any')
        i = checkinput('ipaddress')
        p = checkinput('port')
    except Exception, e:
        raise pException(e)

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
    try:
        nodeid = checkinput('nodeid', 'number')
        g.db.execute("DELETE FROM nodes WHERE id = ?", [nodeid])
        g.db.commit()
        return True
    except Exception, e:
        error = str(e)
        if error == "foreign key constraint failed":
            error = "Is this node still part of a pool?"

        raise pException(error)

def get_nodes():
    o = session['oid']
    q = g.db.execute('SELECT * FROM nodes WHERE owner = ? ORDER BY ip', [ o ])

    return q.fetchall()

def get_node_family(nid):
    q = g.db.execute("SELECT ip FROM nodes WHERE id = ?", [nid])
    r = q.fetchone()['ip']

    if r.startswith('4-'):
        return "4"
    else:
        return "6"

def get_pool_types():
    q = g.db.execute('SELECT * FROM pooltypes');
    return q.fetchall()

def add_pool_node(nid, pid, owner):
    if not check_if_admin():
        raise pException("Permission denied")

    ipfamily = False

    for n in get_pool_nodes(pid):
        if n['ip'] != None:
            ipfamily = get_node_family(n['nodeid'])
            break

    if ipfamily != False and get_node_family(nid) != ipfamily:
        raise pException("You cannot mix IPv4 and IPv6")

    try:
        g.db.execute('INSERT INTO poolnodes (node, pool, owner) \
            VALUES (?, ?, ?)', [ nid, pid, owner ])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def del_pool_node():
    try:
        pnodeid = checkinput('pnid', 'number')
        g.db.execute("DELETE FROM poolnodes WHERE id = ?", [pnodeid])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def add_pool():

    # Do a member-ownership check
    try:
        i = checkinput('poolname', 'any')
        p = checkinput('pooltype', 'number')
        m = checkinput('members[]', 'number')
        oid = session['oid']
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
    try:
        poolid = checkinput('poolid', 'number')
        g.db.execute("DELETE FROM pools WHERE id = ?", [poolid])
        g.db.commit()
        return True
    except Exception, e:
        error = str(e)
        if error == "foreign key constraint failed":
            error = "Is this pool still used by a vip?"

        raise pException(error)

@adminonly
def set_pooltype():
    try:
        poolid = checkinput('poolid', 'number')
        pooltype = checkinput('pooltype', 'number')
        g.db.execute("UPDATE pools SET pooltype = ? WHERE id = ?", [ pooltype, poolid ])
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
    q = g.db.execute('SELECT p.*, n.*, n.id as nodeid, pn.id as pnid FROM pools p, nodes n, poolnodes pn \
        WHERE p.owner = ? and n.id = pn.node and pn.pool = p.id AND p.id = ? ORDER BY n.ip', [ o, poolid ])

    return q.fetchall()

def get_vips():
    o = session['oid']
    q = g.db.execute('SELECT v.*, p.poolname, i.iname FROM vips v, pools p, interfaces i \
        WHERE v.owner = ? AND v.pool = p.id AND i.id = v.interface ORDER BY ip', [ o ])

    return q.fetchall()

@adminonly
def add_vip():

    try:
        i = checkinput('ipaddress')
        p = checkinput('port')
        pl = checkinput('pool', 'number')
        iface = checkinput('iface', 'number')
        o = session['oid']

        ipfamily = False
        for n in get_pool_nodes(pl):
            if n['ip'] != None:
                ipfamily = get_node_family(n['nodeid'])
                break

        if ipfamily == False or ipfamily != ip_convert(i)[0]:
            raise pException("You cannot mix IPv4 and IPv6")

        g.db.execute("INSERT INTO vips (ip, port, pool, interface, owner) \
            VALUES (?, ?, ?, ?, ?)", [ip_convert(i), p, pl, iface, o])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def del_vip():
    try:
        vipid = checkinput('vipid', 'number')
        g.db.execute("DELETE FROM vips WHERE id = ?", [vipid])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

def add_iface():

    try:
        iface = checkinput('iface')

        g.db.execute("INSERT INTO interfaces (iname) \
            VALUES (?)", [iface])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def del_iface():
    try:
        ifaceid = checkinput('ifaceid', 'number')
        g.db.execute("DELETE FROM interfaces WHERE id = ?", [ifaceid])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

def get_ifaces():
    q = g.db.execute('SELECT * FROM interfaces')

    return q.fetchall()

def get_iface(ifaceid):
    q = g.db.execute('SELECT * FROM interfaces WHERE id = ?', [ifaceid])

    return q.fetchone()

def add_vrrp():
    try:
        i = checkinput('ipaddress')
        iface = checkinput('iface', 'number')

        g.db.execute("INSERT INTO vrrp (address, interface) VALUES \
            (?, ?)", [ip_convert(i), iface])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

@adminonly
def del_vrrp():
    try:
        v = checkinput('vrrpid', 'number')
        g.db.execute("DELETE FROM vrrp WHERE id = ?", [v])
        g.db.commit()
        return True
    except Exception, e:
        raise pException(e)

def get_vrrps():
    q = g.db.execute('SELECT v.*, i.iname FROM vrrp v, interfaces i WHERE i.id = v.interface')

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

    return render_template('layout.html')

@app.route('/login', methods=['GET', 'POST'])
def login(doredirect=True):
    error = None
    if request.method == 'POST':
        try:
            u = checkinput('username')
            p = checkinput('password', 'any')
        except Exception, e:
            error = 'Invalid username or password'
            return render_template('login.html', error=error)

        q = g.db.execute('SELECT password FROM users WHERE username = ?', [ u ])
        r = q.fetchone()
        if hashpw(p, r[0]) == r[0]:
            session['logged_in'] = True
            session['username']  = u
            session['oid'] = get_user(name=u)['id']
            flash('You were logged in')
            if doredirect == True:
                return redirect(url_for('show_main'))

            return True

        if doredirect == False:
            return False

        error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/users', methods=['GET', 'POST'])
@needlogin
@adminonly
def users():
    error = None
    if request.method == 'POST':
        try:
            a = checkinput('action')
        except Exception, e:
            return jsonify(error="Could not execute action (%s)" % ( e ))
            
        if a == "add":
            try:
                add_user()
                return jsonify(message="Added user")
            except Exception, e:
                return jsonify(error="Could not add user (%s)" % ( e ))
        elif a == "delete":
            uid = checkinput('uid', 'number')
            u = get_user(uid=uid)['username']
            try:
                del_user()
                return jsonify(message="User deleted")
            except Exception, e:
                return jsonify(error="Could not delete user (%s)" % ( e ))
        if a == "edit":
            try:
                edit_user()
                return jsonify(message="Updated user")
            except Exception, e:
                return jsonify(error="Could not update user (%s)" % ( e ))

    users = get_users()
    return render_template('users.html', users=users)

@app.route('/nodes', methods=['GET', 'POST'])
@needlogin
def nodes():
    error = None
    if request.method == 'POST':
        try:
            a = checkinput('action')
        except Exception, e:
            return jsonify(error="Could not execute action (%s)" % ( e ))

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
@needlogin
def pools():
    error = None
    if request.method == 'POST':
        try:
            a = checkinput('action')
        except Exception, e:
            return jsonify(error="Could not execute action (%s)" % ( e ))

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
                nid = checkinput('nodeid', 'number')
                pid = checkinput('poolid', 'number')
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
        elif a == "ptchange":
            try:
                set_pooltype()
                return jsonify(message="Pooltype changed")
            except Exception, e:
                return jsonify(error="Could not change pooltype (%s)" % (e))

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
@needlogin
def vips():
    error = None
    if request.method == 'POST':
        try:
            a = checkinput('action')
        except Exception, e:
            return jsonify(error="Could not execute action (%s)" % ( e ))

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
    interfaces = get_ifaces()
    return render_template('vips.html', pools=pools, vips=vips, interfaces=interfaces)

@app.route('/commit', methods=['GET', 'POST'])
def commit():
    if request.method == 'POST':
        cmsg = ""
        handle_upload = False
        try:
            cmsg = checkinput('cmsg', 'any')
        except:
            cmsg = "new commit"
    
        now = datetime.now()
        tag = now.strftime("%Y%m%d%H%M%S")
        
        try:
            user = checkinput('username')
            password = checkinput('password')
            sender = checkinput('sender', 'any')
            cmsg = checkinput('cmsg', 'any')
            tag = checkinput('tag', 'any')
            handle_upload = True
        except:
            pass

        if handle_upload == True:
            if login(doredirect=False) == False:
                return jsonify(error="Could not process incoming commit on %s" % getfqdn() )

            try:
                cmsg = "%s (received from %s)" % (cmsg, sender)
                recv_commit(tag, cmsg)
                do_config_export(tag)
                return jsonify(message="Processed incoming commit on %s" % getfqdn())
            except Exception, e:
                return jsonify(error="Could not process incoming commit on %s" % getfqdn() )
        
        try:
            do_commit(tag, cmsg)
            do_config_export(tag)
            return jsonify(message="Commited %s as %s" % (cmsg, tag))
        except Exception, e:
            return jsonify(error="Could not commit: %s" % (e))

    if req_settings_set() == False:
        return render_template('commit.html', need_settings=True)

    commits = get_commits()
    settings = get_settings()

    return render_template('commit.html', history=commits, settings=settings)

@app.route('/settings', methods=['GET', 'POST'])
@needlogin
def settings():
    if request.method == 'POST':
        try:
            a = checkinput('action')
        except Exception, e:
            return jsonify(error="Could not execute action (%s)" % ( e ))

        if a == "save_all":
            try:
                for key in requiredsettings:
                    v = checkinput(key)
                    save_setting(key, v)
                for key in [ 'peer1', 'peer2' ]:
                    try:
                        v = checkinput(key, 'hostname')
                        save_setting(key, v)
                    except:
                        pass
                return jsonify(message="All settings saved")
            except Exception, e:
                return jsonify(error="Could not save settings: %s" % (e))
        elif a == "delete_iface":
            try:
                del_iface()
                return jsonify(message="Interface deleted")
            except Exception, e:
                return jsonify(error="Could not delete interface: %s" % (e))
        elif a == "add_iface":
            try:
                add_iface()
                return jsonify(message="Interface added")
            except Exception, e:
                return jsonify(error="Could not add interface: %s" % (e))
        elif a == "delete_vrrp":
            try:
                del_vrrp()
                return jsonify(message="Address deleted")
            except Exception, e:
                return jsonify(error="Could not delete addres: %s" % (e))
        elif a == "add_vrrp":
            try:
                add_vrrp()
                return jsonify(message="Address added")
            except Exception, e:
                return jsonify(error="Could not add address: %s" % (e))


    settings = get_settings()
    interfaces = get_ifaces()
    vrrp = get_vrrps()
    return render_template('settings.html', settings=settings, interfaces=interfaces, vrrp=vrrp)

@app.route('/stats', defaults={'mode': None, 'node': None})
@app.route('/stats/<mode>', defaults={'node': None})
@app.route('/stats/<mode>/<node>')
def stats(mode, node):
    if mode == "system":
        return "Systeemgrafiekjes"

    return "%s %s" % (mode, node)

@app.route('/graph')
def graph():
    return url_for('static', filename="cache/foo.png")

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='::')

