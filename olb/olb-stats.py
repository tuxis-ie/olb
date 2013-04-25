#!/usr/bin/env python

import netsnmp
import os
import time
from pyrrd.rrd import DataSource, RRA, RRD

sysfetch = {}
sysfetch['cpu'] = {}
sysfetch['cpu']['oid'] = {}
sysfetch['cpu']['ds'] = {}
sysfetch['cpu']['oid']['user']        = '.1.3.6.1.4.1.2021.11.9.0'
sysfetch['cpu']['oid']['system']      = '.1.3.6.1.4.1.2021.11.10.0'
sysfetch['cpu']['oid']['idle']        = '.1.3.6.1.4.1.2021.11.11.0'
sysfetch['cpu']['ds']['user']         = 'GAUGE'
sysfetch['cpu']['ds']['system']       = 'GAUGE'
sysfetch['cpu']['ds']['idle']         = 'GAUGE'

sysfetch['memory'] = {}
sysfetch['memory']['oid'] = {}
sysfetch['memory']['ds'] = {}
sysfetch['memory']['oid']['total']    = '.1.3.6.1.4.1.2021.4.6.0'
sysfetch['memory']['oid']['free']     = '.1.3.6.1.4.1.2021.4.11.0'
sysfetch['memory']['oid']['shared']   = '.1.3.6.1.4.1.2021.4.13.0'
sysfetch['memory']['oid']['buffered'] = '.1.3.6.1.4.1.2021.4.14.0'
sysfetch['memory']['oid']['cached']   = '.1.3.6.1.4.1.2021.4.15.0'
sysfetch['memory']['ds']['total']     = 'GAUGE'
sysfetch['memory']['ds']['free']      = 'GAUGE'
sysfetch['memory']['ds']['shared']    = 'GAUGE'
sysfetch['memory']['ds']['buffered']  = 'GAUGE'
sysfetch['memory']['ds']['cached']    = 'GAUGE'

sysfetch['swap'] = {}
sysfetch['swap']['oid'] = {}
sysfetch['swap']['ds'] = {}
sysfetch['swap']['oid']['total']      = '.1.3.6.1.4.1.2021.4.3.0'
sysfetch['swap']['oid']['free']       = '.1.3.6.1.4.1.2021.4.4.0'
sysfetch['swap']['ds']['total']       = 'GAUGE'
sysfetch['swap']['ds']['free']        = 'GAUGE'

sysfetch['ifaces'] = {}
sysfetch['ifaces']['oid'] = {}
sysfetch['ifaces']['ds'] = {}
sysfetch['ifaces']['oid']['ilist']    = '.1.3.6.1.2.1.2.2.1.1'
sysfetch['ifaces']['oid']['names']    = '.1.3.6.1.2.1.2.2.1.2'
sysfetch['ifaces']['oid']['oin']      = '.1.3.6.1.2.1.2.2.1.10'
sysfetch['ifaces']['oid']['oout']     = '.1.3.6.1.2.1.2.2.1.16'
sysfetch['ifaces']['ds']['oin']       = 'COUNTER'
sysfetch['ifaces']['ds']['oout']      = 'COUNTER'

RRDDIR = "rrd"

now = str(int(time.time()))

def create_rrd(filename, args):
    dses = []
    rras = []

    for ds in args['ds']:
        dses.append(
        DataSource( dsName=ds, dsType=args['ds'][ds], heartbeat=600))
    
    rras.append(RRA(cf='AVERAGE', xff=0.5, steps=1, rows=288))
    rras.append(RRA(cf='AVERAGE', xff=0.5, steps=12, rows=744))
    rras.append(RRA(cf='AVERAGE', xff=0.5, steps=24, rows=1116))
    rras.append(RRA(cf='AVERAGE', xff=0.5, steps=48, rows=2191))
    myRRD = RRD(
        filename, ds=dses, rra=rras, start=int(now)-60)
    myRRD.create()

for stype in sysfetch:
    rrd = ""
    if stype in [ 'cpu', 'memory', 'swap' ]:
        values = []
        values.append(now)
        rrd = os.path.join(RRDDIR, stype+'.rrd')
        if os.path.isfile(rrd) == False:
            print "Create %s" % (rrd)
            create_rrd(rrd, sysfetch[stype])

        myRRD = RRD(rrd)
        for s in sysfetch[stype]['oid']:
            r = netsnmp.snmpget(sysfetch[stype]['oid'][s], Version=1, DestHost='localhost', Community='public')
            values.append(str(r[0]))

        myRRD.bufferValue(':'.join(values))
        myRRD.update()
    if stype == "ifaces":
        for i in netsnmp.snmpwalk(sysfetch[stype]['oid']['ilist'], Version=1, DestHost='localhost', Community='public'):
            values = []
            values.append(now)
            name = netsnmp.snmpget(sysfetch[stype]['oid']['names']+'.'+i, Version=1, DestHost='localhost', Community='public')[0]
            oin  = netsnmp.snmpget(sysfetch[stype]['oid']['oin']+'.'+i, Version=1, DestHost='localhost', Community='public')[0]
            oout = netsnmp.snmpget(sysfetch[stype]['oid']['oout']+'.'+i, Version=1, DestHost='localhost', Community='public')[0]
            rrd = os.path.join(RRDDIR, '_'.join([stype, name])+'.rrd')
            if os.path.isfile(rrd) == False:
                print "Create %s" % (rrd)
                create_rrd(rrd, sysfetch[stype])

            values.append(oin)
            values.append(oout)
            myRRD = RRD(rrd)
            myRRD.bufferValue(':'.join(values))
            myRRD.update()
